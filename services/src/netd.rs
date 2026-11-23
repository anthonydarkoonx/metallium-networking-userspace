//! The network service (role 19): the IP stack (`metallium-net`) behind an endpoint. Programs started with network access
//! hold a send capability to that endpoint (slot 10) and a session page (slot 11); a request is an `IPC_CALL` whose
//! words say what to do and whose page carries names and data, as with the VFS. Every call is answered at once (reads
//! that find nothing say "would block": the caller asks again), so the service never waits for the network while a
//! program waits for the service.
//!
//! A call that says "would block" leaves a *watch* behind: what the program is waiting for (data on a connection, room to
//! write, a connection to accept, a datagram, a name, a ping reply). After every round of work the watches are checked;
//! when one is satisfied the service adds one to the event word at the start of that program's session page (shared
//! memory) and wakes the program, which sleeps on that word instead of asking again every tick.
//!
//! Frames reach it through the rings it shares with the network driver (`netring`); the driver pokes it with a message
//! when there is news and once per tick, and it pokes the driver with `IRQ_RAISE`.
use metallium_net_ring::*;
use metallium_driver_rt::*;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use metallium_net::tcp::{self, State};
use metallium_net::{DnsResult, Io, NetError, Stack};

const BUFS_VA: usize = 0x8030_0000;
const RING_VA: usize = 0x8024_0000;
const SESS_VA: usize = 0xA000_0000; // (in the big window: up to 256 pages)
const DATA: usize = 256;
const MAXIO: usize = 4096 - DATA;
/// File... network sessions: as many as the kernel made (`sysinfo_at(18)`), read once at start.
static NSESS_N: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
fn nsess() -> usize {
    NSESS_N.load(core::sync::atomic::Ordering::Relaxed)
}
const CLOCK: u64 = 34;
const IRQ_RAISE: u64 = 35;
const WAKE_WORD: u64 = 33;
const DRIVER_ROLE: u64 = 18;

// operations
pub const N_STATUS: u64 = 100;
pub const N_PING: u64 = 101;
pub const N_PING_REPLY: u64 = 102;
pub const N_UDP_BIND: u64 = 110;
pub const N_UDP_SEND: u64 = 111;
pub const N_UDP_RECV: u64 = 112;
pub const N_UDP_CLOSE: u64 = 113;
pub const N_TCP_CONNECT: u64 = 120;
pub const N_TCP_STATE: u64 = 121;
pub const N_TCP_WRITE: u64 = 122;
pub const N_TCP_READ: u64 = 123;
pub const N_TCP_CLOSE: u64 = 124;
pub const N_TCP_ABORT: u64 = 125;
pub const N_TCP_LISTEN: u64 = 126;
pub const N_TCP_ACCEPT: u64 = 127;
pub const N_TCP_UNLISTEN: u64 = 128;
pub const N_TCP_NODELAY: u64 = 129;
pub const N_DNS_START: u64 = 130;
pub const N_DNS_RESULT: u64 = 131;
pub const N_DNS_RELEASE: u64 = 132;
pub const N_TCP_SHUTDOWN: u64 = 133;
/// Test only: kill this service (a fault), to see what its clients make of it.
pub const N_CRASH: u64 = 199;

// statuses (word 0 of the reply)
pub const S_OK: u64 = 0;
pub const S_WOULD_BLOCK: u64 = 1;
pub const S_EOF: u64 = 2;
pub const S_NO_ADDRESS: u64 = 3;
pub const S_EXHAUSTED: u64 = 4;
pub const S_IN_USE: u64 = 5;
pub const S_BAD_HANDLE: u64 = 6;
pub const S_INVALID: u64 = 7;
pub const S_FAILED: u64 = 8;

fn now_ms() -> u64 {
    svc(CLOCK, 0, 0, 0, 0, 0)[0] / 1_000_000
}

fn net_err(e: NetError) -> u64 {
    match e {
        NetError::NoAddress => S_NO_ADDRESS,
        NetError::Exhausted => S_EXHAUSTED,
        NetError::InUse => S_IN_USE,
        NetError::BadHandle | NetError::NotConnected => S_BAD_HANDLE,
        NetError::TooBig | NetError::InvalidInput => S_INVALID,
    }
}

fn ip_word(ip: [u8; 4]) -> u64 {
    u32::from_be_bytes(ip) as u64
}

fn word_ip(w: u64) -> [u8; 4] {
    (w as u32).to_be_bytes()
}

/// Who a handle belongs to: a session page and the generation of the program that held it.
type Owner = Option<(u8, u64)>;

struct Session {
    tid: u64,
    gen: u64,
}

/// What a program that was told "would block" is waiting for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    TcpRead(usize),
    TcpWrite(usize),
    TcpConnect(usize),
    Accept(usize),
    UdpRecv(usize),
    Dns(usize),
    Ping,
}

struct Netd {
    stack: Stack,
    tx_free: Vec<usize>,
    tx_pending: VecDeque<Vec<u8>>,
    epoch: u32,
    sessions: Vec<Option<Session>>,
    tcp: Vec<Owner>,
    udp: Vec<Owner>,
    listeners: Vec<Owner>,
    dns: Vec<Owner>,
    echoes: Vec<VecDeque<metallium_net::EchoReply>>,
    watches: Vec<Vec<Want>>,
    last_reap: u64,
    driver_tid: Option<u64>,
    rx_frames: u64,
    ntp: Ntp,
    /// The machine has no wall clock of its own (`CLOCK` op 1 has no answer): the time comes from the network, see `Ntp`.
    needs_time: bool,
}

fn grow(v: &mut Vec<Owner>, i: usize) -> &mut Owner {
    if v.len() <= i {
        v.resize(i + 1, None);
    }
    &mut v[i]
}

impl Netd {
    fn ring(&self, which: usize) -> Ring {
        // SAFETY: the ring page is mapped at RING_VA for the life of this task (`init`), and `which` is one of the ring offsets in it.
        unsafe { Ring::at(va(RING_VA) + which) }
    }

    fn page(&self, k: usize) -> &'static mut [u8; 4096] {
        // SAFETY: `k < nsess()`; SESS_VA + k*0x1000 is session page k, mapped read-write in `netd()` before any request is handled. Only one such reference is live at a time (see its single use); the client program may write the page too, so the contents are treated as untrusted bytes.
        unsafe { &mut *((va(SESS_VA + k * 0x1000)) as *mut [u8; 4096]) }
    }

    /// Frames the driver received.
    fn drain_rx(&mut self, now: u64) {
        // SAFETY: RING_VA is the ring page mapped (checked) in `netd()`; EPOCH is inside it; volatile because the driver task writes it.
        let epoch = unsafe { core::ptr::read_volatile((va(RING_VA) + EPOCH) as *const u32) };
        if epoch != self.epoch {
            // the driver restarted: the rings are new, every transmit slot is free again
            self.epoch = epoch;
            self.tx_free = (0..NTX).collect();
        }
        let (rxq, rxfree) = (self.ring(RXQ), self.ring(RXFREE));
        let mut returned = false;
        for _ in 0..RING_ENTRIES {
            let Some(v) = rxq.pop() else { break };
            let (slot, len) = unpack(v);
            if slot < NRX && len > HDR && len <= SLOT {
                // SAFETY: slot < NRX and len <= SLOT were checked, so the range lies inside the BUFS_VA area mapped in `netd()`; the driver gave this slot away via RXQ and gets it back only through RXFREE, so nothing writes it meanwhile.
                let f = unsafe { core::slice::from_raw_parts((va(BUFS_VA) + slot * SLOT + HDR) as *const u8, len - HDR) };
                self.stack.rx(f, now);
                self.rx_frames += 1;
            }
            if slot < NRX {
                rxfree.push(entry(slot, 0));
                returned = true;
            }
        }
        if returned {
            self.kick_driver();
        }
        // finished transmit slots
        let txdone = self.ring(TXDONE);
        while let Some(v) = txdone.pop() {
            let (slot, _) = unpack(v);
            if slot < NTX && !self.tx_free.contains(&slot) {
                self.tx_free.push(slot);
            }
        }
    }

    fn kick_driver(&self) {
        svc(IRQ_RAISE, 3, 0, 0, 0, 0);
    }

    /// Run the stack's timers and hand the frames it wants sent to the driver.
    fn pump(&mut self, now: u64) {
        self.stack.poll(now);
        while let Some(f) = self.stack.pop_tx() {
            if self.tx_pending.len() < 256 {
                self.tx_pending.push_back(f);
            }
        }
        let txq = self.ring(TXQ);
        let mut pushed = false;
        while !self.tx_pending.is_empty() && !txq.is_full() {
            let Some(slot) = self.tx_free.pop() else { break };
            let f = self.tx_pending.pop_front().unwrap();
            let n = f.len().min(SLOT - HDR);
            // SAFETY: `slot` came from `tx_free`, which only holds values < NTX, so the transmit slot (NRX + slot) lies in the BUFS_VA area; n <= SLOT - HDR; the slot is netd's until pushed to TXQ; `f` is a separate Vec.
            unsafe { core::ptr::copy_nonoverlapping(f.as_ptr(), (va(BUFS_VA) + (NRX + slot) * SLOT + HDR) as *mut u8, n) };
            txq.push(entry(slot, n));
            pushed = true;
        }
        if pushed {
            self.kick_driver();
        }
        // pings that came back go to the session that sent them
        while let Some(r) = self.stack.ping_reply() {
            let k = (r.ident >> 8) as usize;
            if k < nsess() && self.echoes[k].len() < 8 {
                self.echoes[k].push_back(r);
            }
        }
    }

    /// The session (page index) of a calling task, noticing a new program in a reused page.
    fn session_of(&mut self, tid: u64) -> Option<(usize, u64)> {
        let r = sysinfo_at(6, tid);
        let (page, gen, owner) = (r[1] as usize, r[2], r[3]);
        if page >= nsess() {
            return None;
        }
        let stale = self.sessions[page].as_ref().is_some_and(|s| s.gen != gen || s.tid != owner);
        if stale {
            self.release_all(page);
        }
        if self.sessions[page].is_none() {
            self.sessions[page] = Some(Session { tid: owner, gen });
        }
        Some((page, gen))
    }

    /// A program is gone (or its page went to another): everything it held is closed.
    fn release_all(&mut self, k: usize) {
        let me = |o: &Owner| o.is_some_and(|(p, _)| p as usize == k);
        let now = now_ms();
        for i in 0..self.tcp.len() {
            if me(&self.tcp[i]) {
                self.stack.tcp_abort(i, now);
                self.stack.tcp_release(i, now);
                self.tcp[i] = None;
            }
        }
        for i in 0..self.udp.len() {
            if me(&self.udp[i]) {
                self.stack.udp_close(i);
                self.udp[i] = None;
            }
        }
        for i in 0..self.listeners.len() {
            if me(&self.listeners[i]) {
                self.stack.tcp_unlisten(i);
                self.listeners[i] = None;
            }
        }
        for i in 0..self.dns.len() {
            if me(&self.dns[i]) {
                self.stack.dns_release(i);
                self.dns[i] = None;
            }
        }
        self.echoes[k].clear();
        self.watches[k].clear();
        self.sessions[k] = None;
    }

    /// Close the resources of programs that ended without closing them.
    fn reap(&mut self, now: u64) {
        if now < self.last_reap + 100 {
            return;
        }
        self.last_reap = now;
        for k in 0..nsess() {
            if let Some(s) = &self.sessions[k] {
                let r = sysinfo_at(6, s.tid);
                if r[1] as usize != k || r[2] != s.gen {
                    self.release_all(k);
                }
            }
        }
    }

    /// Add one to session `k`'s event word and wake the program(s) sleeping on it.
    fn bump(&self, k: usize) {
        let w = (va(SESS_VA + k * 0x1000)) as *mut u32;
        // SAFETY: `k < nsess()`; word 0 of session page k, mapped read-write in `netd()`; volatile because the client program shares the page (a racing client write can only lose one count).
        unsafe { core::ptr::write_volatile(w, core::ptr::read_volatile(w).wrapping_add(1)) };
        svc(WAKE_WORD, w as u64, usize::MAX as u64, 0, 0, 0);
    }

    fn watch(&mut self, k: usize, w: Want) {
        let v = &mut self.watches[k];
        if !v.contains(&w) && v.len() < 16 {
            v.push(w);
        }
    }

    /// Would the call that said "would block" give another answer now? (Must agree with `handle`: a watch that fires
    /// while the call still blocks would make the program and the service chase each other.)
    fn ready(&self, k: usize, w: Want) -> bool {
        use State::*;
        match w {
            Want::TcpRead(id) => {
                let readable = self.stack.tcp_ready(id).map_or(0, |r| r.0);
                readable > 0 || self.stack.tcp_error(id).is_some() || !matches!(self.stack.tcp_state(id), Some(SynSent | SynReceived | Established | FinWait1 | FinWait2))
            }
            Want::TcpWrite(id) => {
                let space = self.stack.tcp_ready(id).map_or(0, |r| r.1);
                self.stack.tcp_error(id).is_some()
                    || match self.stack.tcp_state(id) {
                        Some(Established | CloseWait) => space > 0,
                        Some(SynSent | SynReceived) => false,
                        _ => true,
                    }
            }
            Want::TcpConnect(id) => self.stack.tcp_error(id).is_some() || !matches!(self.stack.tcp_state(id), Some(SynSent | SynReceived)),
            Want::Accept(l) => self.stack.tcp_accept_ready(l) || !self.listeners.get(l).is_some_and(|o| o.is_some()),
            Want::UdpRecv(id) => self.stack.udp_pending(id),
            Want::Dns(q) => self.stack.dns_result(q) != DnsResult::Pending,
            Want::Ping => !self.echoes[k].is_empty(),
        }
    }

    /// Wake the programs whose watches are satisfied.
    fn notify(&mut self) {
        for k in 0..nsess() {
            if self.watches[k].is_empty() {
                continue;
            }
            let before = self.watches[k].len();
            let mut keep = Vec::new();
            for &w in &self.watches[k] {
                if !self.ready(k, w) {
                    keep.push(w);
                }
            }
            self.watches[k] = keep;
            if self.watches[k].len() != before {
                self.bump(k);
            }
        }
    }

    fn mine(o: &Owner, k: usize, gen: u64) -> bool {
        *o == Some((k as u8, gen))
    }

    fn handle(&mut self, k: usize, gen: u64, w: [u64; 3], now: u64) -> [u64; 3] {
        let pg = self.page(k);
        let owner: Owner = Some((k as u8, gen));
        match w[0] {
            N_STATUS => match self.stack.config() {
                Some(c) => {
                    let dns = c.dns.first().copied().unwrap_or([0; 4]);
                    [S_OK, ip_word(c.addr) | ip_word(c.mask) << 32, ip_word(c.gateway.unwrap_or([0; 4])) | ip_word(dns) << 32]
                }
                None => [S_NO_ADDRESS, 0, 0],
            },
            N_PING => {
                let (ip, ident, seq, len) = (word_ip(w[1]), ((k as u16) << 8) | (w[2] & 0xFF) as u16, (w[2] >> 16) as u16, ((w[2] >> 32) as usize).min(MAXIO));
                match self.stack.ping(ip, ident, seq, &pg[DATA..DATA + len], now) {
                    Ok(()) => [S_OK, 0, 0],
                    Err(e) => [net_err(e), 0, 0],
                }
            }
            N_PING_REPLY => match self.echoes[k].pop_front() {
                Some(r) => {
                    let n = r.data.len().min(MAXIO);
                    pg[DATA..DATA + n].copy_from_slice(&r.data[..n]);
                    [S_OK, (r.ident & 0xFF) as u64 | (r.seq as u64) << 16 | (n as u64) << 32, ip_word(r.from)]
                }
                None => {
                    self.watch(k, Want::Ping);
                    [S_WOULD_BLOCK, 0, 0]
                }
            },
            N_UDP_BIND => match self.stack.udp_bind(w[1] as u16) {
                Ok(id) => {
                    *grow(&mut self.udp, id) = owner;
                    [S_OK, id as u64, self.stack.udp_port(id).unwrap_or(0) as u64]
                }
                Err(e) => [net_err(e), 0, 0],
            },
            N_UDP_SEND => {
                let (id, len) = ((w[1] & 0xFFFF_FFFF) as usize, ((w[1] >> 32) as usize).min(MAXIO));
                if !self.udp.get(id).is_some_and(|o| Self::mine(o, k, gen)) {
                    return [S_BAD_HANDLE, 0, 0];
                }
                match self.stack.udp_send(id, word_ip(w[2]), (w[2] >> 32) as u16, &pg[DATA..DATA + len], now) {
                    Ok(()) => [S_OK, 0, 0],
                    Err(e) => [net_err(e), 0, 0],
                }
            }
            N_UDP_RECV => {
                let id = w[1] as usize;
                if !self.udp.get(id).is_some_and(|o| Self::mine(o, k, gen)) {
                    return [S_BAD_HANDLE, 0, 0];
                }
                match self.stack.udp_recv(id) {
                    Ok(Some((ip, port, d))) => {
                        let n = d.len().min(MAXIO);
                        pg[DATA..DATA + n].copy_from_slice(&d[..n]);
                        [S_OK, n as u64 | (port as u64) << 32, ip_word(ip)]
                    }
                    Ok(None) => {
                        self.watch(k, Want::UdpRecv(id));
                        [S_WOULD_BLOCK, 0, 0]
                    }
                    Err(e) => [net_err(e), 0, 0],
                }
            }
            N_UDP_CLOSE => {
                let id = w[1] as usize;
                if self.udp.get(id).is_some_and(|o| Self::mine(o, k, gen)) {
                    self.stack.udp_close(id);
                    self.udp[id] = None;
                    [S_OK, 0, 0]
                } else {
                    [S_BAD_HANDLE, 0, 0]
                }
            }
            N_TCP_CONNECT => match self.stack.tcp_connect(word_ip(w[1]), w[2] as u16, now) {
                Ok(id) => {
                    *grow(&mut self.tcp, id) = owner;
                    [S_OK, id as u64, 0]
                }
                Err(e) => [net_err(e), 0, 0],
            },
            N_TCP_LISTEN => match self.stack.tcp_listen(w[1] as u16, w[2] as usize) {
                Ok(id) => {
                    *grow(&mut self.listeners, id) = owner;
                    [S_OK, id as u64, 0]
                }
                Err(e) => [net_err(e), 0, 0],
            },
            N_TCP_ACCEPT => {
                let l = w[1] as usize;
                if !self.listeners.get(l).is_some_and(|o| Self::mine(o, k, gen)) {
                    return [S_BAD_HANDLE, 0, 0];
                }
                match self.stack.tcp_accept(l) {
                    Some(id) => {
                        *grow(&mut self.tcp, id) = owner;
                        let (ip, port) = self.stack.tcp_peer(id).unwrap_or(([0; 4], 0));
                        [S_OK, id as u64, ip_word(ip) | (port as u64) << 32]
                    }
                    None => {
                        self.watch(k, Want::Accept(l));
                        [S_WOULD_BLOCK, 0, 0]
                    }
                }
            }
            N_TCP_UNLISTEN => {
                let l = w[1] as usize;
                if self.listeners.get(l).is_some_and(|o| Self::mine(o, k, gen)) {
                    self.stack.tcp_unlisten(l);
                    self.listeners[l] = None;
                    [S_OK, 0, 0]
                } else {
                    [S_BAD_HANDLE, 0, 0]
                }
            }
            N_TCP_STATE | N_TCP_WRITE | N_TCP_READ | N_TCP_CLOSE | N_TCP_ABORT | N_TCP_NODELAY | N_TCP_SHUTDOWN => {
                let id = w[1] as usize;
                if !self.tcp.get(id).is_some_and(|o| Self::mine(o, k, gen)) {
                    return [S_BAD_HANDLE, 0, 0];
                }
                match w[0] {
                    N_TCP_STATE => {
                        let code = match self.stack.tcp_state(id) {
                            Some(State::SynSent | State::SynReceived) => 0,
                            Some(State::Established) => 1,
                            Some(State::CloseWait) => 2, // the peer has finished sending
                            Some(State::FinWait1 | State::FinWait2 | State::Closing | State::LastAck | State::TimeWait) => 3,
                            Some(State::Closed) | None => 4,
                        };
                        let err = match self.stack.tcp_error(id) {
                            None => 0,
                            Some(tcp::Error::Refused) => 1,
                            Some(tcp::Error::Reset) => 2,
                            Some(tcp::Error::TimedOut) => 3,
                        };
                        if code == 0 && err == 0 {
                            self.watch(k, Want::TcpConnect(id));
                        }
                        let (readable, space) = self.stack.tcp_ready(id).unwrap_or((0, 0));
                        [S_OK, code | err << 8, readable as u64 | (space as u64) << 32]
                    }
                    N_TCP_WRITE => {
                        let len = (w[2] as usize).min(MAXIO);
                        match self.stack.tcp_write(id, &pg[DATA..DATA + len], now) {
                            Ok(n) if n > 0 || len == 0 => [S_OK, n as u64, 0],
                            Ok(_) => {
                                self.watch(k, Want::TcpWrite(id));
                                [S_WOULD_BLOCK, 0, 0]
                            }
                            Err(e) => [net_err(e), 0, 0],
                        }
                    }
                    N_TCP_READ => {
                        let max = (w[2] as usize).min(MAXIO);
                        match self.stack.tcp_read(id, &mut pg[DATA..DATA + max], now) {
                            Ok(Io::Data(n)) => [S_OK, n as u64, 0],
                            Ok(Io::Eof) => [S_EOF, 0, 0],
                            Ok(Io::WouldBlock) => {
                                self.watch(k, Want::TcpRead(id));
                                [S_WOULD_BLOCK, 0, 0]
                            }
                            Ok(Io::Failed(e)) => [S_FAILED, match e { tcp::Error::Refused => 1, tcp::Error::Reset => 2, tcp::Error::TimedOut => 3 }, 0],
                            Err(e) => [net_err(e), 0, 0],
                        }
                    }
                    N_TCP_CLOSE => {
                        // the program is done with it: finish the close by ourselves and forget the handle
                        self.stack.tcp_release(id, now);
                        self.tcp[id] = None;
                        [S_OK, 0, 0]
                    }
                    N_TCP_SHUTDOWN => {
                        self.stack.tcp_close(id, now);
                        [S_OK, 0, 0]
                    }
                    N_TCP_ABORT => {
                        self.stack.tcp_abort(id, now);
                        self.stack.tcp_release(id, now);
                        self.tcp[id] = None;
                        [S_OK, 0, 0]
                    }
                    _ => {
                        self.stack.tcp_set_nodelay(id, w[2] != 0);
                        [S_OK, 0, 0]
                    }
                }
            }
            N_DNS_START => {
                let len = (w[1] as usize).min(255);
                let own: [u8; 255] = snapshot(&pg[DATA..DATA + len]);
                let Ok(name) = core::str::from_utf8(&own[..len]) else { return [S_INVALID, 0, 0] };
                let name = String::from(name);
                match self.stack.dns_start(&name, now) {
                    Ok(q) => {
                        *grow(&mut self.dns, q) = owner;
                        [S_OK, q as u64, 0]
                    }
                    Err(e) => [net_err(e), 0, 0],
                }
            }
            N_DNS_RESULT => {
                let q = w[1] as usize;
                if !self.dns.get(q).is_some_and(|o| Self::mine(o, k, gen)) {
                    return [S_BAD_HANDLE, 0, 0];
                }
                match self.stack.dns_result(q) {
                    DnsResult::Pending => {
                        self.watch(k, Want::Dns(q));
                        [S_WOULD_BLOCK, 0, 0]
                    }
                    DnsResult::Addrs(a) => {
                        for (i, ip) in a.iter().take(16).enumerate() {
                            pg[DATA + 4 * i..DATA + 4 * i + 4].copy_from_slice(ip);
                        }
                        [S_OK, a.len().min(16) as u64, 0]
                    }
                    DnsResult::NotFound => [S_FAILED, 1, 0],
                    DnsResult::Failed => [S_FAILED, 2, 0],
                }
            }
            N_DNS_RELEASE => {
                let q = w[1] as usize;
                if self.dns.get(q).is_some_and(|o| Self::mine(o, k, gen)) {
                    self.stack.dns_release(q);
                    self.dns[q] = None;
                    [S_OK, 0, 0]
                } else {
                    [S_BAD_HANDLE, 0, 0]
                }
            }
            N_CRASH => {
                let p = 0x10 as *mut u8;
                // SAFETY: deliberate fault injection: 0x10 is unmapped in every task (images are at 0x8000_0000 or higher), so the store traps and the kernel restarts netd; that is the test.
                unsafe { core::ptr::write_volatile(p, 1) };
                [S_OK, 0, 0]
            }
            _ => [S_INVALID, 0, 0],
        }
    }
}

pub fn netd() -> ! {
    println!("[netd] starting");
    if mem_map(1, BUFS_VA, true) != 0 || mem_map(2, RING_VA, true) != 0 {
        println!("[netd] mapping failed");
        exit(1);
    }
    NSESS_N.store(sysinfo_at(18, 0)[1] as usize, core::sync::atomic::Ordering::Relaxed);
    // (all the session pages are one object, in slot 16)
    if mem_map(16, SESS_VA, true) != 0 {
        println!("[netd] mapping the session pages failed");
        exit(1);
    }
    // the driver publishes the device's MAC when it is up
    // SAFETY: RING_VA mapped (checked) at the top of `netd()`; READY is inside the ring page; volatile because the driver writes it.
    while unsafe { core::ptr::read_volatile((va(RING_VA) + READY) as *const u32) } == 0 {
        sleep(1);
    }
    let mut mac = [0u8; 6];
    for (i, b) in mac.iter_mut().enumerate() {
        // SAFETY: same ring page; INFO + i with i < 6 is the MAC the driver published.
        *b = unsafe { core::ptr::read_volatile((va(RING_VA) + INFO + i) as *const u8) };
    }
    let now = now_ms();
    let seed = svc(CLOCK, 0, 0, 0, 0, 0)[0] ^ (mac[5] as u64) << 40;
    let mut n = Netd {
        stack: Stack::new(mac, seed),
        tx_free: (0..NTX).collect(),
        tx_pending: VecDeque::new(),
        // SAFETY: same mapped ring page; EPOCH is inside it.
        epoch: unsafe { core::ptr::read_volatile((va(RING_VA) + EPOCH) as *const u32) },
        sessions: (0..nsess()).map(|_| None).collect(),
        tcp: Vec::new(),
        udp: Vec::new(),
        listeners: Vec::new(),
        dns: Vec::new(),
        echoes: (0..nsess()).map(|_| VecDeque::new()).collect(),
        watches: (0..nsess()).map(|_| Vec::new()).collect(),
        last_reap: now,
        driver_tid: None,
        rx_frames: 0,
        ntp: Ntp::new(),
        needs_time: svc(CLOCK, 1, 0, 0, 0, 0)[0] as i64 == E_NOSYS,
    };
    n.stack.start_dhcp(now);
    // (a restart of this service: programs sleeping on the old instance's watches find out now, and see their handles are gone)
    for k in 0..nsess() {
        n.bump(k);
    }
    println!("[netd] up, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, asking for an address", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    let mut announced = false;
    loop {
        let m = recv(0);
        let now = now_ms();
        n.drain_rx(now);
        if m.is_call {
            let r = match n.session_of(m.sender) {
                Some((k, gen)) => n.handle(k, gen, m.w, now),
                None => [S_INVALID, 0, 0],
            };
            reply(r);
        } else if n.driver_tid.is_none() && sysinfo_at(3, m.sender)[5] == DRIVER_ROLE {
            n.driver_tid = Some(m.sender);
        }
        n.drain_rx(now);
        n.pump(now);
        if n.needs_time {
            n.ntp.step(&mut n.stack, now);
        }
        n.reap(now);
        n.notify();
        // tell the driver when to wake us next: at the stack's next timer, soon if frames wait for a transmit slot
        let wait = if !n.tx_pending.is_empty() { 1 } else { n.stack.next_timer().map_or(100, |t| (t.saturating_sub(now) + 9) / 10).clamp(1, 100) };
        // SAFETY: same mapped ring page; POLL is inside it (0x814 < 4096); the driver only reads it.
        unsafe { core::ptr::write_volatile((va(RING_VA) + POLL) as *mut u32, wait as u32) };
        if !announced {
            if let Some(c) = n.stack.config() {
                announced = true;
                println!("[netd] address {}.{}.{}.{} (gateway {:?}, dns {:?})", c.addr[0], c.addr[1], c.addr[2], c.addr[3], c.gateway, c.dns);
            }
        }
    }
}


// =====================================================================================================================
// Network time (SNTP, RFC 4330): the board has no battery-backed clock to read, so once the network is up netd asks a time
// server and sets the kernel's wall clock (SETTIME, which only this service may call). Without a wall clock TLS
// cannot check certificate validity dates. Repeats hourly; tries the next server after a failure.
// =====================================================================================================================
const NTP_SERVERS: [&str; 3] = ["pool.ntp.org", "time.cloudflare.com", "time.google.com"];
const NTP_UNIX_OFFSET: u64 = 2_208_988_800; // seconds from 1900 to 1970

enum NtpState {
    Idle(u64),
    Dns { q: usize, since: u64 },
    Query { sock: usize, dst: [u8; 4], sent: u64, nonce: [u8; 8], tries: u8 },
    Done(u64),
}

struct Ntp {
    state: NtpState,
    server: usize,
}

/// (year, month, day, hour, minute, second) of a Unix time, UTC (days-from-civil algorithm).
fn civil(t: u64) -> (u64, u64, u64, u64, u64, u64) {
    let (days, rem) = (t / 86_400, t % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    (y as u64, m as u64, d as u64, rem / 3600, rem % 3600 / 60, rem % 60)
}

impl Ntp {
    fn new() -> Ntp {
        Ntp { state: NtpState::Idle(0), server: 0 }
    }

    fn fail(&mut self, why: &str, now: u64) -> NtpState {
        println!("[ntp] {}: {why}", NTP_SERVERS[self.server % NTP_SERVERS.len()]);
        self.server += 1;
        NtpState::Idle(now + 5_000)
    }

    fn step(&mut self, stack: &mut Stack, now: u64) {
        let st = core::mem::replace(&mut self.state, NtpState::Idle(0));
        self.state = match st {
            NtpState::Idle(at) => {
                if now >= at && stack.config().is_some() {
                    match stack.dns_start(NTP_SERVERS[self.server % NTP_SERVERS.len()], now) {
                        Ok(q) => NtpState::Dns { q, since: now },
                        Err(_) => NtpState::Idle(now + 5_000),
                    }
                } else {
                    NtpState::Idle(at)
                }
            }
            NtpState::Dns { q, since } => match stack.dns_result(q) {
                DnsResult::Pending if now.saturating_sub(since) < 10_000 => NtpState::Dns { q, since },
                DnsResult::Addrs(a) if !a.is_empty() => {
                    stack.dns_release(q);
                    let dst = a[0];
                    // the request: LI 0, version 4, mode 3 (client); a random nonce in the transmit timestamp comes back as the
                    // server's "originate" timestamp, so an answer that is not for this request is ignored
                    let mut nonce = [0u8; 8];
                    let r = svc(GETRANDOM, 0, 0, 0, 0, 0);
                    nonce.copy_from_slice(&if r[0] == 0 { r[1] } else { now.wrapping_mul(0x9E37_79B9_7F4A_7C15) }.to_le_bytes());
                    let mut pkt = [0u8; 48];
                    pkt[0] = 0x23;
                    pkt[40..48].copy_from_slice(&nonce);
                    match stack.udp_bind(0).ok().map(|s| (s, stack.udp_send(s, dst, 123, &pkt, now))) {
                        Some((sock, Ok(()))) => NtpState::Query { sock, dst, sent: now, nonce, tries: 1 },
                        Some((sock, Err(_))) => {
                            stack.udp_close(sock);
                            self.fail("could not send the request", now)
                        }
                        None => self.fail("no free UDP socket", now),
                    }
                }
                DnsResult::Pending => {
                    stack.dns_release(q);
                    self.fail("DNS lookup timed out", now)
                }
                _ => {
                    stack.dns_release(q);
                    self.fail("DNS lookup failed", now)
                }
            },
            NtpState::Query { sock, dst, sent, nonce, tries } => match stack.udp_recv(sock) {
                Ok(Some((_src, 123, d))) if d.len() >= 48 && d[0] & 7 == 4 && d[0] >> 6 != 3 && (1..=15).contains(&d[1]) && d[24..32] == nonce => {
                    stack.udp_close(sock);
                    let secs = u32::from_be_bytes([d[40], d[41], d[42], d[43]]) as u64;
                    let frac_ns = (u32::from_be_bytes([d[44], d[45], d[46], d[47]]) as u64 * 1_000_000_000) >> 32;
                    let rtt = now.saturating_sub(sent);
                    if secs < NTP_UNIX_OFFSET {
                        self.fail("the server's time is before 1970", now)
                    } else {
                        let unix = secs - NTP_UNIX_OFFSET;
                        let ns = unix * 1_000_000_000 + frac_ns + rtt * 500_000; // + half the round trip
                        let r = svc(SETTIME, ns, 0, 0, 0, 0)[0] as i64;
                        let (y, mo, da, h, mi, s) = civil(unix);
                        if r == 0 {
                            println!("[ntp] clock set from {} ({}.{}.{}.{}): {y:04}-{mo:02}-{da:02} {h:02}:{mi:02}:{s:02} UTC, round trip {rtt} ms", NTP_SERVERS[self.server % NTP_SERVERS.len()], dst[0], dst[1], dst[2], dst[3]);
                            NtpState::Done(now + 3_600_000)
                        } else {
                            self.fail(&alloc::format!("the kernel refused the time ({r})"), now)
                        }
                    }
                }
                Ok(Some(_)) => NtpState::Query { sock, dst, sent, nonce, tries }, // not our answer: keep waiting
                _ if now.saturating_sub(sent) < 2_500 => NtpState::Query { sock, dst, sent, nonce, tries },
                _ if tries < 3 => {
                    // no answer: ask again (UDP loses packets)
                    let mut pkt = [0u8; 48];
                    pkt[0] = 0x23;
                    pkt[40..48].copy_from_slice(&nonce);
                    let _ = stack.udp_send(sock, dst, 123, &pkt, now);
                    NtpState::Query { sock, dst, sent: now, nonce, tries: tries + 1 }
                }
                _ => {
                    stack.udp_close(sock);
                    self.fail("no answer", now)
                }
            },
            NtpState::Done(next) => {
                if now >= next {
                    NtpState::Idle(now)
                } else {
                    NtpState::Done(next)
                }
            }
        };
    }
}
