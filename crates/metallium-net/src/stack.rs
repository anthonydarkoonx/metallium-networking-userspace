//! The stack proper: one `Stack` per network interface, driven entirely by its caller. Frames go in with `rx`, time passes
//! with `poll`, frames to send come out of `pop_tx`; sockets are handles into tables the stack owns.
use crate::tcp::{self, Tcb};
use crate::wire::*;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

pub const MTU: usize = 1500;
const ARP_TTL_MS: u64 = 60_000;
const ARP_RETRY_MS: u64 = 1_000;
const ARP_TRIES: u32 = 3;
const MAX_PENDING_ARP: usize = 16;
const UDP_QUEUE: usize = 32;
const MAX_TCP: usize = 64;
const MAX_FRAGMENTS: usize = 8;
const FRAG_TIMEOUT_MS: u64 = 15_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpConfig {
    pub addr: Ip,
    pub mask: Ip,
    pub gateway: Option<Ip>,
    pub dns: Vec<Ip>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// No address yet (DHCP has not finished).
    NoAddress,
    /// No free socket, port or buffer.
    Exhausted,
    /// The port is taken.
    InUse,
    /// A handle that is not (or no longer) a socket.
    BadHandle,
    /// Too large for one packet.
    TooBig,
    NotConnected,
    InvalidInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Io {
    Data(usize),
    /// The peer finished sending.
    Eof,
    WouldBlock,
    Failed(tcp::Error),
}

struct UdpSock {
    port: u16,
    queue: VecDeque<(Ip, u16, Vec<u8>)>,
}

struct Conn {
    tcb: Tcb,
    /// The listener it was born in, until accepted.
    listener: Option<usize>,
    /// The application let go of it: free it once it has closed.
    orphan: bool,
    /// Born from a listener and not yet taken by `tcp_accept`.
    in_accept_queue: bool,
}

struct Listener {
    port: u16,
    backlog: usize,
}

struct Pending {
    next_hop: Ip,
    packet: Vec<u8>,
}

struct ArpEntry {
    mac: Mac,
    expires: u64,
}

struct Frag {
    key: (Ip, Ip, u8, u16),
    pieces: Vec<(usize, Vec<u8>)>,
    total: Option<usize>,
    born: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoReply {
    pub from: Ip,
    pub ident: u16,
    pub seq: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DhcpState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
}

struct DhcpClient {
    state: DhcpState,
    xid: u32,
    server: Ip,
    offered: Ip,
    next_try: u64,
    tries: u32,
    lease_ms: u64,
    bound_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResult {
    Pending,
    Addrs(Vec<Ip>),
    NotFound,
    Failed,
}

struct DnsQuery {
    id: u16,
    name: String,
    sock: usize,
    server: usize,
    tries: u32,
    next_try: u64,
    result: DnsResult,
    in_use: bool,
}

pub struct Stats {
    pub rx_frames: u64,
    pub tx_frames: u64,
    pub rx_bad: u64,
    pub tcp_retransmits: u64,
}

pub struct Stack {
    pub mac: Mac,
    cfg: Option<IpConfig>,
    arp: Vec<(Ip, ArpEntry)>,
    pending: Vec<Pending>,
    arp_asked: Vec<(Ip, u64, u32)>,
    out: VecDeque<Vec<u8>>,
    udp: Vec<Option<UdpSock>>,
    conns: Vec<Option<Conn>>,
    listeners: Vec<Option<Listener>>,
    accepted: VecDeque<(usize, usize)>, // (listener, conn) ready to be taken
    echo: VecDeque<EchoReply>,
    dhcp: DhcpClient,
    dhcp_enabled: bool,
    dns: Vec<DnsQuery>,
    frags: Vec<Frag>,
    ip_id: u16,
    secret: u64,
    next_port: u16,
    last_icmp_error: u64,
    pub stats: Stats,
}

fn hash(secret: u64, parts: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64 ^ secret;
    for &b in parts {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h ^ (h >> 29)
}

fn same_net(a: Ip, b: Ip, mask: Ip) -> bool {
    (0..4).all(|i| a[i] & mask[i] == b[i] & mask[i])
}

impl Stack {
    pub fn new(mac: Mac, seed: u64) -> Stack {
        Stack {
            mac,
            cfg: None,
            arp: Vec::new(),
            pending: Vec::new(),
            arp_asked: Vec::new(),
            out: VecDeque::new(),
            udp: Vec::new(),
            conns: Vec::new(),
            listeners: Vec::new(),
            accepted: VecDeque::new(),
            echo: VecDeque::new(),
            dhcp: DhcpClient { state: DhcpState::Init, xid: 0, server: ANY_IP, offered: ANY_IP, next_try: 0, tries: 0, lease_ms: 0, bound_at: 0 },
            dhcp_enabled: false,
            dns: Vec::new(),
            frags: Vec::new(),
            ip_id: (seed >> 16) as u16,
            secret: hash(seed, &mac),
            next_port: 49152 + (seed % 16000) as u16,
            last_icmp_error: 0,
            stats: Stats { rx_frames: 0, tx_frames: 0, rx_bad: 0, tcp_retransmits: 0 },
        }
    }

    // ---- configuration -------------------------------------------------------------------------------------------------

    pub fn config(&self) -> Option<&IpConfig> {
        self.cfg.as_ref()
    }

    pub fn set_static(&mut self, cfg: IpConfig) {
        self.cfg = Some(cfg);
        self.dhcp_enabled = false;
    }

    /// Ask a DHCP server for an address (and keep it renewed).
    pub fn start_dhcp(&mut self, now: u64) {
        self.dhcp_enabled = true;
        self.dhcp.state = DhcpState::Init;
        self.dhcp.next_try = now;
        self.dhcp.tries = 0;
    }

    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.out.pop_front()
    }

    fn emit(&mut self, frame: Vec<u8>) {
        self.stats.tx_frames += 1;
        self.out.push_back(frame);
    }

    // ---- sending IP ------------------------------------------------------------------------------------------------------

    fn next_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }

    fn send_ip_from(&mut self, src: Ip, dst: Ip, proto: u8, payload: &[u8], now: u64) {
        let id = self.next_id();
        let packet = build_ipv4(src, dst, proto, id, 64, payload);
        if dst == BROADCAST_IP || self.cfg.as_ref().is_some_and(|c| dst == directed_broadcast(c)) {
            let f = build_eth(BROADCAST_MAC, self.mac, ETH_IPV4, &packet);
            self.emit(f);
            return;
        }
        let Some(cfg) = self.cfg.clone() else { return };
        let next_hop = if same_net(dst, cfg.addr, cfg.mask) { dst } else { cfg.gateway.unwrap_or(dst) };
        match self.arp.iter().find(|(ip, e)| *ip == next_hop && e.expires > now) {
            Some((_, e)) => {
                let f = build_eth(e.mac, self.mac, ETH_IPV4, &packet);
                self.emit(f);
            }
            None => {
                if self.pending.len() >= MAX_PENDING_ARP {
                    self.pending.remove(0);
                }
                self.pending.push(Pending { next_hop, packet });
                self.ask_arp(next_hop, now);
            }
        }
    }

    fn send_ip(&mut self, dst: Ip, proto: u8, payload: &[u8], now: u64) -> Result<(), NetError> {
        let src = self.cfg.as_ref().ok_or(NetError::NoAddress)?.addr;
        self.send_ip_from(src, dst, proto, payload, now);
        Ok(())
    }

    fn ask_arp(&mut self, target: Ip, now: u64) {
        if let Some(a) = self.arp_asked.iter_mut().find(|a| a.0 == target) {
            if now < a.1 + ARP_RETRY_MS {
                return;
            }
            a.1 = now;
            a.2 += 1;
        } else {
            self.arp_asked.push((target, now, 1));
        }
        let Some(cfg) = &self.cfg else { return };
        let req = Arp { op: ARP_REQUEST, sha: self.mac, spa: cfg.addr, tha: [0; 6], tpa: target };
        let f = build_eth(BROADCAST_MAC, self.mac, ETH_ARP, &req.build());
        self.emit(f);
    }

    fn learn(&mut self, ip: Ip, mac: Mac, now: u64) {
        if ip == ANY_IP || mac == BROADCAST_MAC {
            return;
        }
        match self.arp.iter_mut().find(|(i, _)| *i == ip) {
            Some((_, e)) => *e = ArpEntry { mac, expires: now + ARP_TTL_MS },
            None => {
                if self.arp.len() >= 64 {
                    self.arp.remove(0);
                }
                self.arp.push((ip, ArpEntry { mac, expires: now + ARP_TTL_MS }));
            }
        }
        self.arp_asked.retain(|a| a.0 != ip);
        // packets that waited for this address
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].next_hop == ip {
                let p = self.pending.remove(i);
                let f = build_eth(mac, self.mac, ETH_IPV4, &p.packet);
                self.emit(f);
            } else {
                i += 1;
            }
        }
    }

    // ---- receiving -------------------------------------------------------------------------------------------------------------

    pub fn rx(&mut self, frame: &[u8], now: u64) {
        self.stats.rx_frames += 1;
        let Some(eth) = Eth::parse(frame) else { return self.stats.rx_bad += 1 };
        if eth.dst != self.mac && eth.dst != BROADCAST_MAC && eth.dst[0] & 1 == 0 {
            return; // not for us
        }
        match eth.ethertype {
            ETH_ARP => self.rx_arp(eth.payload, now),
            ETH_IPV4 => self.rx_ipv4(eth.src, eth.payload, now),
            _ => {}
        }
    }

    fn rx_arp(&mut self, p: &[u8], now: u64) {
        let Some(a) = Arp::parse(p) else { return self.stats.rx_bad += 1 };
        let Some(cfg) = self.cfg.clone() else { return };
        if a.tpa == cfg.addr {
            self.learn(a.spa, a.sha, now);
            if a.op == ARP_REQUEST {
                let reply = Arp { op: ARP_REPLY, sha: self.mac, spa: cfg.addr, tha: a.sha, tpa: a.spa };
                let f = build_eth(a.sha, self.mac, ETH_ARP, &reply.build());
                self.emit(f);
            }
        } else if self.arp.iter().any(|(ip, _)| *ip == a.spa) {
            self.learn(a.spa, a.sha, now); // (refresh what we already knew)
        }
    }

    fn for_us(&self, dst: Ip) -> bool {
        match &self.cfg {
            Some(c) => dst == c.addr || dst == BROADCAST_IP || dst == directed_broadcast(c),
            None => dst == BROADCAST_IP || self.dhcp_enabled, // (before we have an address only DHCP replies matter)
        }
    }

    fn rx_ipv4(&mut self, src_mac: Mac, p: &[u8], now: u64) {
        let Some(ip) = Ipv4::parse(p) else { return self.stats.rx_bad += 1 };
        if !self.for_us(ip.dst) {
            return;
        }
        if let Some(c) = &self.cfg {
            if same_net(ip.src, c.addr, c.mask) {
                self.learn(ip.src, src_mac, now);
            }
        }
        if ip.is_fragment() {
            let Some(whole) = self.reassemble(&ip, now) else { return };
            return self.dispatch(ip.src, ip.dst, ip.proto, &whole, now);
        }
        self.dispatch(ip.src, ip.dst, ip.proto, ip.payload, now);
    }

    fn reassemble(&mut self, ip: &Ipv4, now: u64) -> Option<Vec<u8>> {
        let key = (ip.src, ip.dst, ip.proto, ip.id);
        if ip.frag_offset + ip.payload.len() > 64 * 1024 {
            return None;
        }
        let at = match self.frags.iter().position(|f| f.key == key) {
            Some(i) => i,
            None => {
                if self.frags.len() >= MAX_FRAGMENTS {
                    self.frags.remove(0);
                }
                self.frags.push(Frag { key, pieces: Vec::new(), total: None, born: now });
                self.frags.len() - 1
            }
        };
        let f = &mut self.frags[at];
        f.pieces.retain(|(o, _)| *o != ip.frag_offset);
        f.pieces.push((ip.frag_offset, ip.payload.to_vec()));
        if !ip.more_fragments {
            f.total = Some(ip.frag_offset + ip.payload.len());
        }
        let total = f.total?;
        f.pieces.sort_by_key(|(o, _)| *o);
        let mut data = Vec::with_capacity(total);
        for (o, piece) in &f.pieces {
            if *o > data.len() {
                return None; // a hole
            }
            if o + piece.len() > data.len() {
                data.extend_from_slice(&piece[data.len() - o..]);
            }
        }
        if data.len() < total {
            return None;
        }
        data.truncate(total);
        self.frags.remove(at);
        Some(data)
    }

    fn dispatch(&mut self, src: Ip, dst: Ip, proto: u8, payload: &[u8], now: u64) {
        match proto {
            PROTO_ICMP => self.rx_icmp(src, payload, now),
            PROTO_UDP => self.rx_udp(src, dst, payload, now),
            PROTO_TCP => self.rx_tcp(src, dst, payload, now),
            _ => {}
        }
    }

    fn rx_icmp(&mut self, src: Ip, p: &[u8], now: u64) {
        let Some(m) = Icmp::parse(p) else { return self.stats.rx_bad += 1 };
        match m.kind {
            ICMP_ECHO_REQUEST => {
                let reply = build_icmp(ICMP_ECHO_REPLY, 0, m.rest, m.payload);
                let _ = self.send_ip(src, PROTO_ICMP, &reply, now);
            }
            ICMP_ECHO_REPLY => {
                if self.echo.len() < 32 {
                    self.echo.push_back(EchoReply { from: src, ident: u16::from_be_bytes([m.rest[0], m.rest[1]]), seq: u16::from_be_bytes([m.rest[2], m.rest[3]]), data: m.payload.to_vec() });
                }
            }
            ICMP_UNREACHABLE => {
                // the start of our packet is quoted: a TCP connection attempt to a closed port (or a dead host) can give up
                if let Some(inner) = Ipv4::parse_quoted(m.payload) {
                    if inner.proto == PROTO_TCP && inner.payload.len() >= 8 {
                        let (sp, dp) = (u16::from_be_bytes([inner.payload[0], inner.payload[1]]), u16::from_be_bytes([inner.payload[2], inner.payload[3]]));
                        for c in self.conns.iter_mut().flatten() {
                            if c.tcb.local == (inner.src, sp) && c.tcb.remote == (inner.dst, dp) && c.tcb.state == tcp::State::SynSent && m.code == 3 {
                                let _ = c.tcb.abort();
                                c.tcb.error = Some(tcp::Error::Refused);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn rx_udp(&mut self, src: Ip, dst: Ip, p: &[u8], now: u64) {
        let Some(u) = Udp::parse(src, dst, p) else { return self.stats.rx_bad += 1 };
        if u.dst_port == DHCP_CLIENT_PORT && self.dhcp_enabled {
            return self.rx_dhcp(u.payload, now);
        }
        if let Some(s) = self.udp.iter_mut().flatten().find(|s| s.port == u.dst_port) {
            if s.queue.len() < UDP_QUEUE {
                s.queue.push_back((src, u.src_port, u.payload.to_vec()));
            }
            return;
        }
        // nobody listens: port unreachable (not for broadcasts, and not too often)
        if dst != BROADCAST_IP && now >= self.last_icmp_error + 10 {
            self.last_icmp_error = now;
            let mut quoted = build_ipv4(src, dst, PROTO_UDP, 0, 64, &p[..p.len().min(8)]);
            quoted.truncate(28);
            let m = build_icmp(ICMP_UNREACHABLE, 3, [0; 4], &quoted);
            let _ = self.send_ip(src, PROTO_ICMP, &m, now);
        }
    }

    fn rx_tcp(&mut self, src: Ip, dst: Ip, p: &[u8], now: u64) {
        let Some(seg) = Tcp::parse(src, dst, p) else { return self.stats.rx_bad += 1 };
        if self.cfg.as_ref().map_or(true, |c| c.addr != dst) {
            return;
        }
        let idx = self.conns.iter().position(|c| c.as_ref().is_some_and(|c| c.tcb.local == (dst, seg.dst_port) && c.tcb.remote == (src, seg.src_port) && !c.tcb.is_closed()));
        if let Some(i) = idx {
            let reply = self.conns[i].as_mut().unwrap().tcb.segment(&seg, now);
            if let Some(r) = reply {
                self.send_tcp(dst, src, seg.dst_port, seg.src_port, &r, now);
            }
            self.after_segment(i);
            self.flush(i, now);
            return;
        }
        // no connection: a SYN for a listener starts one, anything else gets a reset (RFC 9293 3.10.7.1)
        if seg.flags & SYN != 0 && seg.flags & (ACK | RST) == 0 {
            if let Some(l) = self.listeners.iter().position(|l| l.as_ref().is_some_and(|l| l.port == seg.dst_port)) {
                let queued = self.conns.iter().flatten().filter(|c| c.listener == Some(l)).count();
                let backlog = self.listeners[l].as_ref().unwrap().backlog;
                if queued < backlog && self.conns.iter().flatten().count() < MAX_TCP {
                    let iss = self.isn((dst, seg.dst_port), (src, seg.src_port), now);
                    let tcb = Tcb::accept((dst, seg.dst_port), (src, seg.src_port), &seg, iss, tcp::Config::default());
                    let i = self.add_conn(Conn { tcb, listener: Some(l), orphan: false, in_accept_queue: false });
                    self.flush(i, now);
                }
                return; // (a full backlog drops the SYN: the peer retries)
            }
        }
        if seg.flags & RST == 0 {
            let rst = if seg.flags & ACK != 0 {
                tcp::OutSeg { flags: RST, seq: seg.ack, ack: 0, window: 0, mss: None, window_scale: None, payload: Vec::new() }
            } else {
                tcp::OutSeg { flags: RST | ACK, seq: 0, ack: seg.seq.wrapping_add(seg.seq_len()), window: 0, mss: None, window_scale: None, payload: Vec::new() }
            };
            self.send_tcp(dst, src, seg.dst_port, seg.src_port, &rst, now);
        }
    }

    fn isn(&self, local: (Ip, u16), remote: (Ip, u16), now: u64) -> u32 {
        let mut t = [0u8; 12];
        t[0..4].copy_from_slice(&local.0);
        t[4..6].copy_from_slice(&local.1.to_be_bytes());
        t[6..10].copy_from_slice(&remote.0);
        t[10..12].copy_from_slice(&remote.1.to_be_bytes());
        (hash(self.secret, &t) as u32).wrapping_add((now as u32).wrapping_mul(250))
    }

    fn add_conn(&mut self, c: Conn) -> usize {
        match self.conns.iter().position(|x| x.is_none()) {
            Some(i) => {
                self.conns[i] = Some(c);
                i
            }
            None => {
                self.conns.push(Some(c));
                self.conns.len() - 1
            }
        }
    }

    /// After a segment: a connection that finished its handshake in a listener's queue becomes acceptable.
    fn after_segment(&mut self, i: usize) {
        if let Some(c) = self.conns[i].as_mut() {
            if let (Some(l), false) = (c.listener, c.in_accept_queue) {
                if c.tcb.is_established() {
                    c.in_accept_queue = true;
                    self.accepted.push_back((l, i));
                }
            }
        }
    }

    fn send_tcp(&mut self, src: Ip, dst: Ip, sp: u16, dp: u16, s: &tcp::OutSeg, now: u64) {
        let seg = build_tcp(src, dst, &TcpOut { src_port: sp, dst_port: dp, seq: s.seq, ack: s.ack, flags: s.flags, window: s.window, mss: s.mss, window_scale: s.window_scale, payload: &s.payload });
        self.send_ip_from(src, dst, PROTO_TCP, &seg, now);
    }

    /// Send whatever connection `i` wants to send, and free it if it is finished and abandoned.
    fn flush(&mut self, i: usize, now: u64) {
        let Some(c) = self.conns[i].as_mut() else { return };
        let segs = c.tcb.output(now);
        let (local, remote) = (c.tcb.local, c.tcb.remote);
        for s in &segs {
            if s.payload.is_empty() && s.flags & (SYN | FIN) == 0 {
                // (a pure ACK)
            }
            self.send_tcp(local.0, remote.0, local.1, remote.1, s, now);
        }
        let c = self.conns[i].as_ref().unwrap();
        if c.tcb.is_closed() && (c.orphan || (c.listener.is_some() && !c.in_accept_queue)) {
            self.conns[i] = None;
        }
    }

    // ---- time ----------------------------------------------------------------------------------------------------------------

    /// When `poll` next has something to do (None: nothing pending).
    pub fn next_timer(&self) -> Option<u64> {
        let mut t: Option<u64> = None;
        let mut note = |x: u64| t = Some(t.map_or(x, |y| y.min(x)));
        for c in self.conns.iter().flatten() {
            if let Some(d) = c.tcb.next_deadline() {
                note(d);
            }
        }
        if self.dhcp_enabled {
            note(self.dhcp.next_try);
        }
        for q in self.dns.iter().filter(|q| q.in_use && q.result == DnsResult::Pending) {
            note(q.next_try);
        }
        for a in &self.arp_asked {
            note(a.1 + ARP_RETRY_MS);
        }
        for f in &self.frags {
            note(f.born + FRAG_TIMEOUT_MS);
        }
        t
    }

    pub fn poll(&mut self, now: u64) {
        for i in 0..self.conns.len() {
            if self.conns[i].is_some() {
                let before = self.conns[i].as_ref().unwrap().tcb.state;
                self.flush(i, now);
                self.after_segment_if_alive(i);
                let _ = before;
            }
        }
        self.dhcp_poll(now);
        self.dns_poll(now);
        // ARP: give up on addresses that never answer
        let mut dead = Vec::new();
        for a in self.arp_asked.clone() {
            if now >= a.1 + ARP_RETRY_MS {
                if a.2 >= ARP_TRIES {
                    dead.push(a.0);
                } else {
                    self.ask_arp(a.0, now);
                }
            }
        }
        for ip in dead {
            self.arp_asked.retain(|a| a.0 != ip);
            self.pending.retain(|p| p.next_hop != ip);
        }
        self.frags.retain(|f| now < f.born + FRAG_TIMEOUT_MS);
        self.arp.retain(|(_, e)| e.expires > now);
    }

    fn after_segment_if_alive(&mut self, i: usize) {
        if self.conns[i].is_some() {
            self.after_segment(i);
        }
    }

    // ---- DHCP ------------------------------------------------------------------------------------------------------------------

    fn dhcp_send(&mut self, msg_type: u8, now: u64) {
        let d = &self.dhcp;
        let m = Dhcp {
            op: 1,
            xid: d.xid,
            chaddr: self.mac,
            msg_type,
            requested_ip: (msg_type == DHCP_REQUEST && d.state != DhcpState::Renewing).then_some(d.offered),
            server_id: (msg_type == DHCP_REQUEST && d.state != DhcpState::Renewing).then_some(d.server),
            ..Dhcp::default()
        };
        let body = m.build();
        if d.state == DhcpState::Renewing {
            if let Some(c) = &self.cfg {
                // (the checksum covers the addresses: build the datagram for the ones it is sent with)
                let (src, server) = (c.addr, d.server);
                let udp = build_udp(src, server, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &body);
                self.send_ip_from(src, server, PROTO_UDP, &udp, now);
                return;
            }
        }
        let udp = build_udp(ANY_IP, BROADCAST_IP, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, &body);
        self.send_ip_from(ANY_IP, BROADCAST_IP, PROTO_UDP, &udp, now);
    }

    fn dhcp_poll(&mut self, now: u64) {
        if !self.dhcp_enabled || now < self.dhcp.next_try {
            return;
        }
        let backoff = |tries: u32| 1000u64 << tries.min(4);
        match self.dhcp.state {
            DhcpState::Init | DhcpState::Selecting => {
                if self.dhcp.state == DhcpState::Init || self.dhcp.tries == 0 {
                    self.dhcp.xid = hash(self.secret, &now.to_le_bytes()) as u32;
                }
                self.dhcp.state = DhcpState::Selecting;
                self.dhcp_send(DHCP_DISCOVER, now);
                self.dhcp.next_try = now + backoff(self.dhcp.tries);
                self.dhcp.tries += 1;
            }
            DhcpState::Requesting => {
                if self.dhcp.tries > 4 {
                    self.dhcp.state = DhcpState::Init;
                    self.dhcp.tries = 0;
                    self.dhcp.next_try = now;
                    return;
                }
                self.dhcp_send(DHCP_REQUEST, now);
                self.dhcp.next_try = now + backoff(self.dhcp.tries);
                self.dhcp.tries += 1;
            }
            DhcpState::Bound => {
                // half the lease is over: renew with the server that gave it
                self.dhcp.state = DhcpState::Renewing;
                self.dhcp.tries = 0;
                self.dhcp.xid = hash(self.secret, &now.to_le_bytes()) as u32;
                self.dhcp_send(DHCP_REQUEST, now);
                self.dhcp.next_try = now + 5_000;
            }
            DhcpState::Renewing => {
                if now >= self.dhcp.bound_at + self.dhcp.lease_ms {
                    // the lease ran out: the address is gone
                    self.cfg = None;
                    self.dhcp.state = DhcpState::Init;
                    self.dhcp.next_try = now;
                    self.dhcp.tries = 0;
                } else {
                    self.dhcp_send(DHCP_REQUEST, now);
                    self.dhcp.next_try = now + 5_000;
                }
            }
        }
    }

    fn rx_dhcp(&mut self, p: &[u8], now: u64) {
        let Some(m) = Dhcp::parse(p) else { return };
        if m.op != 2 || m.xid != self.dhcp.xid || m.chaddr != self.mac {
            return;
        }
        match (self.dhcp.state, m.msg_type) {
            (DhcpState::Selecting, DHCP_OFFER) => {
                self.dhcp.offered = m.yiaddr;
                self.dhcp.server = m.server_id.unwrap_or(ANY_IP);
                self.dhcp.state = DhcpState::Requesting;
                self.dhcp.tries = 0;
                self.dhcp_send(DHCP_REQUEST, now);
                self.dhcp.next_try = now + 1000;
            }
            (DhcpState::Requesting | DhcpState::Renewing, DHCP_ACK) => {
                let lease = m.lease_secs.unwrap_or(3600) as u64 * 1000;
                self.cfg = Some(IpConfig { addr: m.yiaddr, mask: m.subnet_mask.unwrap_or([255, 255, 255, 0]), gateway: m.router, dns: m.dns.clone() });
                self.dhcp.state = DhcpState::Bound;
                self.dhcp.lease_ms = lease;
                self.dhcp.bound_at = now;
                self.dhcp.next_try = now + lease / 2;
                if let Some(s) = m.server_id {
                    self.dhcp.server = s;
                }
            }
            (DhcpState::Requesting | DhcpState::Renewing, DHCP_NAK) => {
                self.cfg = None;
                self.dhcp.state = DhcpState::Init;
                self.dhcp.next_try = now;
                self.dhcp.tries = 0;
            }
            _ => {}
        }
    }

    pub fn dhcp_bound(&self) -> bool {
        self.dhcp_enabled && matches!(self.dhcp.state, DhcpState::Bound | DhcpState::Renewing)
    }

    // ---- ping --------------------------------------------------------------------------------------------------------------------

    pub fn ping(&mut self, dst: Ip, ident: u16, seq: u16, data: &[u8], now: u64) -> Result<(), NetError> {
        if data.len() > MTU - 28 {
            return Err(NetError::TooBig);
        }
        let mut rest = [0u8; 4];
        rest[0..2].copy_from_slice(&ident.to_be_bytes());
        rest[2..4].copy_from_slice(&seq.to_be_bytes());
        self.send_ip(dst, PROTO_ICMP, &build_icmp(ICMP_ECHO_REQUEST, 0, rest, data), now)
    }

    pub fn ping_reply(&mut self) -> Option<EchoReply> {
        self.echo.pop_front()
    }

    // ---- UDP sockets -----------------------------------------------------------------------------------------------------------------

    fn port_free(&self, port: u16) -> bool {
        !self.udp.iter().flatten().any(|s| s.port == port) && !self.listeners.iter().flatten().any(|l| l.port == port) && !self.conns.iter().flatten().any(|c| c.tcb.local.1 == port && !c.tcb.is_closed())
    }

    fn ephemeral(&mut self) -> Option<u16> {
        for _ in 0..16384 {
            let p = self.next_port;
            self.next_port = if self.next_port == 65535 { 49152 } else { self.next_port + 1 };
            if self.port_free(p) {
                return Some(p);
            }
        }
        None
    }

    /// Open a UDP socket on `port` (0 = any free one); the socket handle.
    pub fn udp_bind(&mut self, port: u16) -> Result<usize, NetError> {
        let port = if port == 0 {
            self.ephemeral().ok_or(NetError::Exhausted)?
        } else if self.udp.iter().flatten().any(|s| s.port == port) {
            return Err(NetError::InUse);
        } else {
            port
        };
        let s = UdpSock { port, queue: VecDeque::new() };
        if let Some(i) = self.udp.iter().position(|x| x.is_none()) {
            self.udp[i] = Some(s);
            return Ok(i);
        }
        if self.udp.len() >= 64 {
            return Err(NetError::Exhausted);
        }
        self.udp.push(Some(s));
        Ok(self.udp.len() - 1)
    }

    pub fn udp_port(&self, id: usize) -> Option<u16> {
        self.udp.get(id)?.as_ref().map(|s| s.port)
    }

    pub fn udp_send(&mut self, id: usize, dst: Ip, port: u16, data: &[u8], now: u64) -> Result<(), NetError> {
        let src_port = self.udp.get(id).and_then(|s| s.as_ref()).ok_or(NetError::BadHandle)?.port;
        if data.len() > MTU - 28 {
            return Err(NetError::TooBig);
        }
        let src = self.cfg.as_ref().ok_or(NetError::NoAddress)?.addr;
        let seg = build_udp(src, dst, src_port, port, data);
        self.send_ip(dst, PROTO_UDP, &seg, now)
    }

    pub fn udp_recv(&mut self, id: usize) -> Result<Option<(Ip, u16, Vec<u8>)>, NetError> {
        Ok(self.udp.get_mut(id).and_then(|s| s.as_mut()).ok_or(NetError::BadHandle)?.queue.pop_front())
    }

    /// Would `udp_recv` return something now (a datagram, or an error because the socket is gone)?
    pub fn udp_pending(&self, id: usize) -> bool {
        self.udp.get(id).and_then(|s| s.as_ref()).map_or(true, |s| !s.queue.is_empty())
    }

    pub fn udp_close(&mut self, id: usize) {
        if let Some(s) = self.udp.get_mut(id) {
            *s = None;
        }
    }

    // ---- DNS ---------------------------------------------------------------------------------------------------------------------------

    /// Start resolving `name` (a host name; the A records). Poll `dns_result`.
    pub fn dns_start(&mut self, name: &str, now: u64) -> Result<usize, NetError> {
        if build_dns_query(0, name).is_none() {
            return Err(NetError::InvalidInput);
        }
        let sock = self.udp_bind(0)?;
        let id = (hash(self.secret, &now.to_le_bytes()) & 0xFFFF) as u16;
        let q = DnsQuery { id, name: String::from(name), sock, server: 0, tries: 0, next_try: now, result: DnsResult::Pending, in_use: true };
        let slot = match self.dns.iter().position(|q| !q.in_use) {
            Some(i) => {
                self.dns[i] = q;
                i
            }
            None => {
                self.dns.push(q);
                self.dns.len() - 1
            }
        };
        self.dns_poll(now);
        Ok(slot)
    }

    pub fn dns_result(&self, q: usize) -> DnsResult {
        self.dns.get(q).filter(|q| q.in_use).map_or(DnsResult::Failed, |q| q.result.clone())
    }

    pub fn dns_release(&mut self, q: usize) {
        if let Some(query) = self.dns.get_mut(q) {
            if query.in_use {
                query.in_use = false;
                let s = query.sock;
                self.udp_close(s);
            }
        }
    }

    fn dns_poll(&mut self, now: u64) {
        for i in 0..self.dns.len() {
            if !self.dns[i].in_use || self.dns[i].result != DnsResult::Pending {
                continue;
            }
            // an answer?
            let sock = self.dns[i].sock;
            while let Ok(Some((_, _, msg))) = self.udp_recv(sock) {
                if let Some(a) = parse_dns_response(&msg) {
                    let q = &mut self.dns[i];
                    if a.id == q.id && a.question.eq_ignore_ascii_case(&q.name) {
                        q.result = match (a.rcode, a.addrs.is_empty()) {
                            (0, false) => DnsResult::Addrs(a.addrs),
                            (3, _) | (0, true) => DnsResult::NotFound,
                            _ => DnsResult::Failed,
                        };
                    }
                }
            }
            let q = &self.dns[i];
            if q.result != DnsResult::Pending || now < q.next_try {
                continue;
            }
            let servers = self.cfg.as_ref().map(|c| c.dns.clone()).unwrap_or_default();
            if servers.is_empty() || q.tries >= 6 {
                self.dns[i].result = DnsResult::Failed;
                continue;
            }
            let server = servers[q.server % servers.len()];
            let msg = build_dns_query(q.id, &q.name).unwrap();
            let _ = self.udp_send(sock, server, DNS_PORT, &msg, now);
            let q = &mut self.dns[i];
            q.tries += 1;
            q.server += 1;
            q.next_try = now + 1000 * (1 << (q.tries / 2).min(3));
        }
    }

    // ---- TCP sockets -----------------------------------------------------------------------------------------------------------------------

    pub fn tcp_listen(&mut self, port: u16, backlog: usize) -> Result<usize, NetError> {
        if port == 0 || !self.port_free(port) {
            return Err(NetError::InUse);
        }
        let l = Listener { port, backlog: backlog.clamp(1, 16) };
        match self.listeners.iter().position(|x| x.is_none()) {
            Some(i) => {
                self.listeners[i] = Some(l);
                Ok(i)
            }
            None => {
                self.listeners.push(Some(l));
                Ok(self.listeners.len() - 1)
            }
        }
    }

    pub fn tcp_unlisten(&mut self, l: usize) {
        if let Some(slot) = self.listeners.get_mut(l) {
            *slot = None;
        }
        // connections that were never accepted go away with it
        for i in 0..self.conns.len() {
            if self.conns[i].as_ref().is_some_and(|c| c.listener == Some(l) && c.in_accept_queue_or_pending()) {
                let rst = self.conns[i].as_mut().unwrap().tcb.abort();
                let (local, remote) = {
                    let c = self.conns[i].as_ref().unwrap();
                    (c.tcb.local, c.tcb.remote)
                };
                if let Some(r) = rst {
                    self.send_tcp(local.0, remote.0, local.1, remote.1, &r, 0);
                }
                self.conns[i] = None;
            }
        }
        self.accepted.retain(|a| a.0 != l);
    }

    /// Is a connection waiting on listener `l`?
    pub fn tcp_accept_ready(&self, l: usize) -> bool {
        self.accepted.iter().any(|a| a.0 == l)
    }

    /// The next connection that completed its handshake on listener `l`.
    pub fn tcp_accept(&mut self, l: usize) -> Option<usize> {
        let at = self.accepted.iter().position(|a| a.0 == l)?;
        let (_, c) = self.accepted.remove(at)?;
        if let Some(conn) = self.conns[c].as_mut() {
            conn.listener = None;
        }
        Some(c)
    }

    pub fn tcp_connect(&mut self, dst: Ip, port: u16, now: u64) -> Result<usize, NetError> {
        let src = self.cfg.as_ref().ok_or(NetError::NoAddress)?.addr;
        if self.conns.iter().flatten().count() >= MAX_TCP {
            return Err(NetError::Exhausted);
        }
        let local_port = self.ephemeral().ok_or(NetError::Exhausted)?;
        let iss = self.isn((src, local_port), (dst, port), now);
        let tcb = Tcb::connect((src, local_port), (dst, port), iss, tcp::Config::default());
        let i = self.add_conn(Conn { tcb, listener: None, orphan: false, in_accept_queue: false });
        self.flush(i, now);
        Ok(i)
    }

    fn conn(&mut self, id: usize) -> Result<&mut Conn, NetError> {
        self.conns.get_mut(id).and_then(|c| c.as_mut()).ok_or(NetError::BadHandle)
    }

    pub fn tcp_state(&self, id: usize) -> Option<tcp::State> {
        self.conns.get(id)?.as_ref().map(|c| c.tcb.state)
    }

    pub fn tcp_error(&self, id: usize) -> Option<tcp::Error> {
        self.conns.get(id)?.as_ref().and_then(|c| c.tcb.error)
    }

    pub fn tcp_peer(&self, id: usize) -> Option<(Ip, u16)> {
        self.conns.get(id)?.as_ref().map(|c| c.tcb.remote)
    }

    pub fn tcp_write(&mut self, id: usize, data: &[u8], now: u64) -> Result<usize, NetError> {
        let c = self.conn(id)?;
        if c.tcb.error.is_some() || c.tcb.is_closed() {
            return Err(NetError::NotConnected);
        }
        let n = c.tcb.write(data);
        self.flush(id, now);
        Ok(n)
    }

    pub fn tcp_read(&mut self, id: usize, buf: &mut [u8], now: u64) -> Result<Io, NetError> {
        let c = self.conn(id)?;
        let n = c.tcb.read(buf);
        let r = if n > 0 {
            Io::Data(n)
        } else if let Some(e) = c.tcb.error {
            Io::Failed(e)
        } else if c.tcb.at_eof() || c.tcb.is_closed() {
            Io::Eof
        } else {
            Io::WouldBlock
        };
        self.flush(id, now); // (reading may have opened the window)
        Ok(r)
    }

    /// Bytes waiting to be read, and room to write.
    pub fn tcp_ready(&self, id: usize) -> Option<(usize, usize)> {
        let c = self.conns.get(id)?.as_ref()?;
        Some((c.tcb.readable(), c.tcb.send_space()))
    }

    pub fn tcp_close(&mut self, id: usize, now: u64) {
        if let Some(Some(c)) = self.conns.get_mut(id) {
            c.tcb.close();
        }
        self.flush(id, now);
    }

    pub fn tcp_abort(&mut self, id: usize, now: u64) {
        let Some(Some(c)) = self.conns.get_mut(id) else { return };
        let (local, remote) = (c.tcb.local, c.tcb.remote);
        if let Some(r) = c.tcb.abort() {
            self.send_tcp(local.0, remote.0, local.1, remote.1, &r, now);
        }
        self.flush(id, now);
    }

    /// The application lets go of the handle: the connection finishes closing by itself and is then freed.
    pub fn tcp_release(&mut self, id: usize, now: u64) {
        if let Some(Some(c)) = self.conns.get_mut(id) {
            c.orphan = true;
            c.tcb.close();
        }
        self.flush(id, now);
    }

    pub fn tcp_set_nodelay(&mut self, id: usize, on: bool) {
        if let Some(Some(c)) = self.conns.get_mut(id) {
            c.tcb.set_nodelay(on);
        }
    }

    pub fn tcp_summary(&self, id: usize) -> alloc::string::String {
        self.conns.get(id).and_then(|c| c.as_ref()).map(|c| c.tcb.summary()).unwrap_or_default()
    }

    pub fn connection_count(&self) -> usize {
        self.conns.iter().flatten().count()
    }
}

impl Conn {
    fn in_accept_queue_or_pending(&self) -> bool {
        self.listener.is_some()
    }
}

fn directed_broadcast(c: &IpConfig) -> Ip {
    let mut b = [0u8; 4];
    for i in 0..4 {
        b[i] = c.addr[i] | !c.mask[i];
    }
    b
}

impl<'a> Ipv4<'a> {
    /// Parse the start of a packet quoted inside an ICMP error: the header is complete, the payload only partly there.
    pub fn parse_quoted(p: &'a [u8]) -> Option<Ipv4<'a>> {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let ihl = (p[0] & 0xF) as usize * 4;
        if ihl < 20 || p.len() < ihl {
            return None;
        }
        Some(Ipv4 { src: p[12..16].try_into().unwrap(), dst: p[16..20].try_into().unwrap(), proto: p[9], ttl: p[8], id: 0, dont_fragment: false, more_fragments: false, frag_offset: 0, payload: &p[ihl..] })
    }
}

impl Stack {
    /// Where the DHCP client is (diagnostics): state name, tries, next try.
    pub fn dhcp_debug(&self) -> alloc::string::String {
        alloc::format!("{:?} tries={} next_try={} lease_ms={} bound_at={}", self.dhcp.state, self.dhcp.tries, self.dhcp.next_try, self.dhcp.lease_ms, self.dhcp.bound_at)
    }
}
