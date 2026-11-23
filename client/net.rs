//! Networking: UDP sockets, TCP streams and listeners, name lookup and ping, over the network service (`netd`).
//! A program needs network access from its parent (the spawn request's network flag): the service's endpoint is then in
//! slot 10 and the program's session page in slot 11. All calls are answered at once by the service; the blocking
//! forms below ask again when the service says something may have changed (it bumps and wakes the event word at the start
//! of the session page, shared memory, so a waiting program sleeps instead of polling) until the answer is no longer
//! "would block" (or the timeout is over); a wake-up that never comes costs at most half a second.
use crate::io::{self, Error, ErrorKind, Read, Write};
use crate::thread::Mutex as RawMutex;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};
use core::time::Duration;

const EP: u64 = 10;
const PAGE_SLOT: u64 = 11;
/// Where the session page is mapped (the kernel chooses; set when `MAPPED` becomes 1).
static VA_AT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn va() -> usize {
    VA_AT.load(Ordering::Relaxed)
}

/// Map the session page, once; whether it is mapped.
fn map_page() -> u8 {
    let r = crate::map_anywhere(PAGE_SLOT, true);
    if r >= 0 {
        VA_AT.store(r as usize, Ordering::Relaxed);
        1
    } else {
        2
    }
}
const DATA: usize = 256;
const MAXIO: usize = 4096 - DATA;

// operations and statuses: see user/src/netd.rs
const N_STATUS: u64 = 100;
const N_PING: u64 = 101;
const N_PING_REPLY: u64 = 102;
const N_UDP_BIND: u64 = 110;
const N_UDP_SEND: u64 = 111;
const N_UDP_RECV: u64 = 112;
const N_UDP_CLOSE: u64 = 113;
const N_TCP_CONNECT: u64 = 120;
const N_TCP_STATE: u64 = 121;
const N_TCP_WRITE: u64 = 122;
const N_TCP_READ: u64 = 123;
const N_TCP_CLOSE: u64 = 124;
const N_TCP_ABORT: u64 = 125;
const N_TCP_LISTEN: u64 = 126;
const N_TCP_ACCEPT: u64 = 127;
const N_TCP_UNLISTEN: u64 = 128;
const N_TCP_NODELAY: u64 = 129;
const N_DNS_START: u64 = 130;
const N_DNS_RESULT: u64 = 131;
const N_DNS_RELEASE: u64 = 132;
const N_TCP_SHUTDOWN: u64 = 133;
pub const N_CRASH: u64 = 199;

const S_OK: u64 = 0;
const S_WOULD_BLOCK: u64 = 1;
const S_EOF: u64 = 2;
const S_NO_ADDRESS: u64 = 3;
const S_EXHAUSTED: u64 = 4;
const S_IN_USE: u64 = 5;
const S_BAD_HANDLE: u64 = 6;
const S_FAILED: u64 = 8;

static LOCK: RawMutex = RawMutex::new();
static CALLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Calls made to the network service so far (a test hook: a blocked program should make almost none).
pub fn service_calls() -> u32 {
    CALLS.load(Ordering::Relaxed)
}
static MAPPED: AtomicU8 = AtomicU8::new(0); // 0 not yet, 1 mapped, 2 no network access

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr([a, b, c, d])
    }

    pub fn parse(s: &str) -> Option<Ipv4Addr> {
        let mut out = [0u8; 4];
        let mut it = s.split('.');
        for o in out.iter_mut() {
            *o = it.next()?.parse().ok()?;
        }
        it.next().is_none().then_some(Ipv4Addr(out))
    }

    fn word(&self) -> u64 {
        u32::from_be_bytes(self.0) as u64
    }

    fn from_word(w: u64) -> Ipv4Addr {
        Ipv4Addr((w as u32).to_be_bytes())
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SocketAddr {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl SocketAddr {
    pub const fn new(ip: Ipv4Addr, port: u16) -> SocketAddr {
        SocketAddr { ip, port }
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Option<Ipv4Addr>,
}

fn status_error(s: u64, detail: u64) -> Error {
    let kind = match s {
        S_WOULD_BLOCK => ErrorKind::WouldBlock,
        S_NO_ADDRESS => ErrorKind::AddrNotAvailable,
        S_EXHAUSTED => ErrorKind::OutOfMemory,
        S_IN_USE => ErrorKind::AddrInUse,
        S_BAD_HANDLE => ErrorKind::NotConnected,
        S_FAILED => match detail {
            1 => ErrorKind::ConnectionRefused,
            2 => ErrorKind::ConnectionReset,
            3 => ErrorKind::TimedOut,
            _ => ErrorKind::Other,
        },
        _ => ErrorKind::InvalidInput,
    };
    Error { kind, code: s as i64 }
}

/// Call the service with the session page mapped and the program's network lock held. `f` gets the page.
fn rpc<T>(op: u64, a: u64, b: u64, fill: impl FnOnce(&mut [u8; 4096]), take: impl FnOnce(&[u64; 3], &[u8; 4096]) -> T) -> io::Result<T> {
    LOCK.lock();
    CALLS.fetch_add(1, Ordering::Relaxed);
    if MAPPED.load(Ordering::Relaxed) == 0 {
        MAPPED.store(map_page(), Ordering::Relaxed);
    }
    let r = if MAPPED.load(Ordering::Relaxed) != 1 {
        Err(Error::new(ErrorKind::PermissionDenied))
    } else {
        // SAFETY: `MAPPED == 1` means `va()` is the mapped 4096-byte session page; the lock is held, so no other thread of
        // this program touches it. The service writes it while we are inside `call`, so the references do not live across it:
        // `fill` gets one before, `take` gets a new one after.
        fill(unsafe { &mut *(va() as *mut [u8; 4096]) });
        match crate::call(EP, [op, a, b]) {
            // SAFETY: as above (page mapped, lock held); `call` has returned, so the service is no longer writing the page, and this shared reference ends when `take` does.
            (0, r) if r[0] == S_OK => Ok(take(&r, unsafe { &*(va() as *const [u8; 4096]) })),
            (0, r) => Err(status_error(r[0], r[1])),
            (e, _) => Err(Error::from_kernel(e)),
        }
    };
    LOCK.unlock();
    r
}

fn simple(op: u64, a: u64, b: u64) -> io::Result<[u64; 3]> {
    rpc(op, a, b, |_| {}, |r, _| *r)
}

/// Our address, mask, gateway and name server; `AddrNotAvailable` until DHCP has finished.
pub fn config() -> io::Result<Config> {
    let r = simple(N_STATUS, 0, 0)?;
    let nz = |w: u64| (w != 0).then(|| Ipv4Addr::from_word(w));
    Ok(Config { addr: Ipv4Addr::from_word(r[1] & 0xFFFF_FFFF), mask: Ipv4Addr::from_word(r[1] >> 32), gateway: nz(r[2] & 0xFFFF_FFFF), dns: nz(r[2] >> 32) })
}

/// Wait until the machine has an address.
pub fn wait_for_address(timeout: Duration) -> io::Result<Config> {
    let end = crate::time::Instant::now() + timeout;
    loop {
        match config() {
            Err(e) if e.kind == ErrorKind::AddrNotAvailable && crate::time::Instant::now() < end => crate::sleep(2),
            r => return r,
        }
    }
}

fn mapped() -> bool {
    // Under the lock, so two threads cannot both map the page, and the state read here is the state `map_page` wrote.
    LOCK.lock();
    if MAPPED.load(Ordering::Relaxed) == 0 {
        MAPPED.store(map_page(), Ordering::Relaxed);
    }
    let m = MAPPED.load(Ordering::Relaxed) == 1;
    LOCK.unlock();
    m
}

/// The session's event counter: the service adds one and wakes whoever waits on it whenever something a "would block"
/// answer was waiting for may have happened. Read it *before* the call that may say "would block".
fn event() -> u32 {
    // Under the lock: `rpc` holds it for the whole of its call, so no `&mut` over the session page is live while the word is read,
    // and it is read atomically (the service updates it from another task).
    LOCK.lock();
    if MAPPED.load(Ordering::Relaxed) == 0 {
        MAPPED.store(map_page(), Ordering::Relaxed);
    }
    let v = if MAPPED.load(Ordering::Relaxed) == 1 {
        // SAFETY: `MAPPED == 1`, so `va()` is the mapped session page; offset 0 is a 4-aligned word that lives as long as the mapping.
        unsafe { core::sync::atomic::AtomicU32::from_ptr(va() as *mut u32) }.load(Ordering::Acquire)
    } else {
        0
    };
    LOCK.unlock();
    v
}

/// Sleep until the event counter is no longer `seen` (or `remaining` is over, or half a second, whichever is first).
fn pause(seen: u32, remaining: Option<Duration>) {
    if !mapped() {
        crate::sleep(1);
        return;
    }
    let mut ticks = 50u64;
    if let Some(r) = remaining {
        ticks = ticks.min((r.as_millis() as u64 + 9) / 10);
    }
    if ticks > 0 {
        crate::svc(crate::thread::WAIT_WORD, va() as u64, seen as u64, ticks, 0, 0);
    }
}

fn left(timeout: Duration, t0: &crate::time::Instant) -> Duration {
    timeout.saturating_sub(t0.elapsed())
}

/// Send one echo request and wait for the answer; the round trip time.
pub fn ping(dst: Ipv4Addr, payload: &[u8], timeout: Duration) -> io::Result<Duration> {
    static SEQ: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) as u16;
    let ident = 0x42u64;
    let t0 = crate::time::Instant::now();
    let len = payload.len().min(MAXIO);
    rpc(N_PING, dst.word(), ident | (seq as u64) << 16 | (len as u64) << 32, |p| p[DATA..DATA + len].copy_from_slice(&payload[..len]), |_, _| ())?;
    loop {
        let seen = event();
        match rpc(N_PING_REPLY, 0, 0, |_| {}, |r, _| r[1]) {
            Ok(w) if (w >> 16) as u16 == seq => return Ok(t0.elapsed()),
            Ok(_) => {} // (an answer to an earlier request)
            Err(e) if e.kind == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        if t0.elapsed() > timeout {
            return Err(Error::new(ErrorKind::TimedOut));
        }
        pause(seen, Some(left(timeout, &t0)));
    }
}

/// The addresses of a host name: a dotted-quad is itself, `localhost` is 127.0.0.1, anything else asks the name server.
pub fn lookup_host(name: &str) -> io::Result<Vec<Ipv4Addr>> {
    if let Some(a) = Ipv4Addr::parse(name) {
        return Ok(alloc::vec![a]);
    }
    if name.eq_ignore_ascii_case("localhost") {
        return Ok(alloc::vec![Ipv4Addr::new(127, 0, 0, 1)]);
    }
    let n = name.len().min(255);
    let q = rpc(N_DNS_START, n as u64, 0, |p| p[DATA..DATA + n].copy_from_slice(&name.as_bytes()[..n]), |r, _| r[1])?;
    let t0 = crate::time::Instant::now();
    let out = loop {
        let seen = event();
        match rpc(N_DNS_RESULT, q, 0, |_| {}, |r, p| (0..r[1] as usize).map(|i| Ipv4Addr([p[DATA + 4 * i], p[DATA + 4 * i + 1], p[DATA + 4 * i + 2], p[DATA + 4 * i + 3]])).collect::<Vec<_>>()) {
            Ok(v) => break Ok(v),
            Err(e) if e.kind == ErrorKind::WouldBlock => {}
            Err(e) => break Err(if e.code == S_FAILED as i64 { Error::new(ErrorKind::NotFound) } else { e }),
        }
        if t0.elapsed() > Duration::from_secs(20) {
            break Err(Error::new(ErrorKind::TimedOut));
        }
        pause(seen, Some(left(Duration::from_secs(20), &t0)));
    };
    let _ = simple(N_DNS_RELEASE, q, 0);
    out
}

// ---- UDP --------------------------------------------------------------------------------------------------------------------

pub struct UdpSocket {
    id: u64,
    port: u16,
    timeout: Option<Duration>,
}

impl UdpSocket {
    /// Bind to a local port (0: any free one).
    pub fn bind(port: u16) -> io::Result<UdpSocket> {
        let r = simple(N_UDP_BIND, port as u64, 0)?;
        Ok(UdpSocket { id: r[1], port: r[2] as u16, timeout: None })
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    pub fn set_read_timeout(&mut self, t: Option<Duration>) {
        self.timeout = t;
    }

    pub fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<usize> {
        let n = data.len().min(MAXIO);
        rpc(N_UDP_SEND, self.id | (n as u64) << 32, to.ip.word() | (to.port as u64) << 32, |p| p[DATA..DATA + n].copy_from_slice(&data[..n]), |_, _| ())?;
        Ok(n)
    }

    /// The next datagram if one has arrived.
    pub fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        rpc(N_UDP_RECV, self.id, 0, |_| {}, |r, p| {
            let n = ((r[1] & 0xFFFF_FFFF) as usize).min(buf.len());
            buf[..n].copy_from_slice(&p[DATA..DATA + n]);
            (n, SocketAddr::new(Ipv4Addr::from_word(r[2]), (r[1] >> 32) as u16))
        })
    }

    /// Wait for a datagram (up to the read timeout, if one is set).
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let t0 = crate::time::Instant::now();
        loop {
            let seen = event();
            match self.try_recv_from(buf) {
                Err(e) if e.kind == ErrorKind::WouldBlock => {}
                r => return r,
            }
            if self.timeout.is_some_and(|t| t0.elapsed() >= t) {
                return Err(Error::new(ErrorKind::TimedOut));
            }
            pause(seen, self.timeout.map(|t| left(t, &t0)));
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let _ = simple(N_UDP_CLOSE, self.id, 0);
    }
}

// ---- TCP --------------------------------------------------------------------------------------------------------------------

pub struct TcpStream {
    id: u64,
    peer: SocketAddr,
    nonblocking: bool,
    timeout: Option<Duration>,
}

/// (state, error, readable, space): state 0 connecting, 1 established, 2 the peer has finished sending, 3 closing, 4 closed.
fn tcp_state(id: u64) -> io::Result<(u64, u64, usize, usize)> {
    let r = simple(N_TCP_STATE, id, 0)?;
    Ok((r[1] & 0xFF, (r[1] >> 8) & 0xFF, (r[2] & 0xFFFF_FFFF) as usize, (r[2] >> 32) as usize))
}

fn conn_error(code: u64) -> Error {
    Error::new(match code {
        1 => ErrorKind::ConnectionRefused,
        2 => ErrorKind::ConnectionReset,
        3 => ErrorKind::TimedOut,
        _ => ErrorKind::Other,
    })
}

impl TcpStream {
    pub fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(addr, Duration::from_secs(30))
    }

    pub fn connect_timeout(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        let id = simple(N_TCP_CONNECT, addr.ip.word(), addr.port as u64)?[1];
        let s = TcpStream { id, peer: addr, nonblocking: false, timeout: None };
        let t0 = crate::time::Instant::now();
        loop {
            let seen = event();
            match tcp_state(id)? {
                (1 | 2, ..) => return Ok(s),
                (4, e, ..) => return Err(conn_error(e)), // (dropping `s` forgets the handle)
                _ => {}
            }
            if t0.elapsed() > timeout {
                return Err(Error::new(ErrorKind::TimedOut));
            }
            pause(seen, Some(left(timeout, &t0)));
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub fn set_nonblocking(&mut self, on: bool) {
        self.nonblocking = on;
    }

    pub fn set_read_timeout(&mut self, t: Option<Duration>) {
        self.timeout = t;
    }

    pub fn set_nodelay(&self, on: bool) -> io::Result<()> {
        simple(N_TCP_NODELAY, self.id, on as u64).map(|_| ())
    }

    /// Finish sending (the peer sees the end of the stream); reading still works.
    pub fn shutdown_write(&self) -> io::Result<()> {
        simple(N_TCP_SHUTDOWN, self.id, 0).map(|_| ())
    }

    /// Drop the connection with a reset instead of closing it politely.
    pub fn abort(self) {
        let _ = simple(N_TCP_ABORT, self.id, 0);
        core::mem::forget(self);
    }

    fn read_once(&self, buf: &mut [u8]) -> io::Result<usize> {
        let max = buf.len().min(MAXIO);
        match rpc(N_TCP_READ, self.id, max as u64, |_| {}, |r, p| {
            let n = r[1] as usize;
            buf[..n].copy_from_slice(&p[DATA..DATA + n]);
            n
        }) {
            Err(e) if e.code == S_EOF as i64 => Ok(0),
            r => r,
        }
    }

    fn write_once(&self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(MAXIO);
        rpc(N_TCP_WRITE, self.id, n as u64, |p| p[DATA..DATA + n].copy_from_slice(&data[..n]), |r, _| r[1] as usize)
    }
}

impl Read for TcpStream {
    /// Bytes from the stream; 0 at its end. Blocks (up to the read timeout) unless the stream is non-blocking.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let t0 = crate::time::Instant::now();
        loop {
            let seen = event();
            match self.read_once(buf) {
                Err(e) if e.kind == ErrorKind::WouldBlock && !self.nonblocking => {}
                r => return r,
            }
            if self.timeout.is_some_and(|t| t0.elapsed() >= t) {
                return Err(Error::new(ErrorKind::TimedOut));
            }
            pause(seen, self.timeout.map(|t| left(t, &t0)));
        }
    }
}

impl Write for TcpStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        loop {
            let seen = event();
            match self.write_once(data) {
                Err(e) if e.kind == ErrorKind::WouldBlock && !self.nonblocking => {}
                r => return r,
            }
            pause(seen, None);
        }
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = simple(N_TCP_CLOSE, self.id, 0);
    }
}

pub struct TcpListener {
    id: u64,
    port: u16,
}

impl TcpListener {
    pub fn bind(port: u16, backlog: usize) -> io::Result<TcpListener> {
        let id = simple(N_TCP_LISTEN, port as u64, backlog as u64)?[1];
        Ok(TcpListener { id, port })
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// The next connection, if one is waiting.
    pub fn try_accept(&self) -> io::Result<TcpStream> {
        let r = simple(N_TCP_ACCEPT, self.id, 0)?;
        Ok(TcpStream { id: r[1], peer: SocketAddr::new(Ipv4Addr::from_word(r[2] & 0xFFFF_FFFF), (r[2] >> 32) as u16), nonblocking: false, timeout: None })
    }

    /// Wait for a connection (at most `timeout`, if given).
    pub fn accept(&self, timeout: Option<Duration>) -> io::Result<TcpStream> {
        let t0 = crate::time::Instant::now();
        loop {
            let seen = event();
            match self.try_accept() {
                Err(e) if e.kind == ErrorKind::WouldBlock => {}
                r => return r,
            }
            if timeout.is_some_and(|t| t0.elapsed() >= t) {
                return Err(Error::new(ErrorKind::TimedOut));
            }
            pause(seen, timeout.map(|t| left(t, &t0)));
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let _ = simple(N_TCP_UNLISTEN, self.id, 0);
    }
}

/// Test hook: make the network service fault.
pub fn crash_service() {
    let _ = simple(N_CRASH, 0, 0);
}

#[allow(dead_code)]
fn unused(_: String) {}
