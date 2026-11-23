extern crate std;
use super::*;
use crate::tcp::State;
use crate::wire::*;
use alloc::vec::Vec;

// ---- wire formats ---------------------------------------------------------------------------------------------------------

#[test]
fn checksum_matches_rfc1071_example() {
    // RFC 1071 section 3: 00 01 f2 03 f4 f5 f6 f7 sums to ddf2 (before complement)
    let d = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(fold(sum16(&d, 0)), 0xddf2);
    assert_eq!(checksum(&d), 0x220d);
    assert_eq!(checksum(&[0xAB]), !0xAB00);
    // a buffer with its own checksum filled in sums to zero
    let mut p = std::vec![0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    assert_eq!(checksum(&p), 0);
}

#[test]
fn ipv4_roundtrip_and_corruption() {
    let p = build_ipv4([10, 0, 0, 1], [10, 0, 0, 2], PROTO_UDP, 77, 64, b"hello");
    let ip = Ipv4::parse(&p).unwrap();
    assert_eq!((ip.src, ip.dst, ip.proto, ip.id, ip.payload), ([10, 0, 0, 1], [10, 0, 0, 2], PROTO_UDP, 77, &b"hello"[..]));
    assert!(ip.dont_fragment && !ip.is_fragment());
    for i in 0..20 {
        let mut q = p.clone();
        q[i] ^= 0x10;
        if i == 8 || i == 10 || i == 11 {
            continue; // (ttl and checksum flips also change the sum: all must be refused except by luck)
        }
        assert!(Ipv4::parse(&q).is_none() || i == 1, "byte {i}");
    }
    // trailing Ethernet padding is cut off by the total length
    let mut padded = p.clone();
    padded.extend_from_slice(&[0; 20]);
    assert_eq!(Ipv4::parse(&padded).unwrap().payload, b"hello");
    assert!(Ipv4::parse(&p[..p.len() - 1]).is_none());
}

#[test]
fn udp_tcp_arp_roundtrip() {
    let (a, b) = ([192, 168, 1, 1], [192, 168, 1, 2]);
    let u = build_udp(a, b, 1000, 53, b"query");
    let pu = Udp::parse(a, b, &u).unwrap();
    assert_eq!((pu.src_port, pu.dst_port, pu.payload), (1000, 53, &b"query"[..]));
    let mut bad = u.clone();
    bad[9] ^= 1;
    assert!(Udp::parse(a, b, &bad).is_none());
    assert!(Udp::parse(b, a, &u).is_some(), "the pseudo-header sum is symmetric in the addresses");
    assert!(Udp::parse(a, [1, 1, 1, 1], &u).is_none());
    let t = build_tcp(a, b, &TcpOut { src_port: 5, dst_port: 80, seq: 0xFFFF_FF00, ack: 7, flags: SYN | ACK, window: 4096, mss: Some(1460), window_scale: Some(7), payload: b"" });
    let pt = Tcp::parse(a, b, &t).unwrap();
    assert_eq!((pt.seq, pt.ack, pt.flags, pt.window, pt.options.mss, pt.options.window_scale), (0xFFFF_FF00, 7, SYN | ACK, 4096, Some(1460), Some(7)));
    assert_eq!(pt.seq_len(), 1);
    let arp = Arp { op: ARP_REQUEST, sha: [1, 2, 3, 4, 5, 6], spa: a, tha: [0; 6], tpa: b };
    assert_eq!(Arp::parse(&arp.build()), Some(arp));
    let f = build_eth(BROADCAST_MAC, [1, 2, 3, 4, 5, 6], ETH_ARP, &arp.build());
    assert_eq!(f.len(), 60);
    assert_eq!(Eth::parse(&f).unwrap().ethertype, ETH_ARP);
}

#[test]
fn tcp_options_with_junk_do_not_panic() {
    let a = [1, 2, 3, 4];
    let mut t = build_tcp(a, a, &TcpOut { src_port: 1, dst_port: 2, seq: 1, ack: 0, flags: SYN, window: 1, mss: Some(1460), window_scale: Some(3), payload: b"" });
    for kind in 0..=255u8 {
        for len in [0u8, 1, 2, 3, 4, 200] {
            t[20] = kind;
            t[21] = len;
            t[16] = 0;
            t[17] = 0;
            let c = !fold(sum16(&t, pseudo_sum(a, a, PROTO_TCP, t.len())));
            t[16..18].copy_from_slice(&c.to_be_bytes());
            let _ = Tcp::parse(a, a, &t);
        }
    }
}

#[test]
fn dhcp_roundtrip() {
    let m = Dhcp { op: 2, xid: 0xDEAD_BEEF, yiaddr: [10, 0, 2, 15], chaddr: [1, 2, 3, 4, 5, 6], msg_type: DHCP_ACK, subnet_mask: Some([255, 255, 255, 0]), router: Some([10, 0, 2, 2]), dns: std::vec![[10, 0, 2, 3], [8, 8, 8, 8]], lease_secs: Some(86400), server_id: Some([10, 0, 2, 2]), requested_ip: None };
    assert_eq!(Dhcp::parse(&m.build()), Some(m));
    assert!(Dhcp::parse(&[0; 100]).is_none());
}

#[test]
fn dns_names_compression_and_cname() {
    let q = build_dns_query(0x1234, "www.example.com").unwrap();
    assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x00]);
    assert_eq!(&q[12..16], &[3, b'w', b'w', b'w']);
    assert!(build_dns_query(1, &"a".repeat(64)).is_none());
    assert!(build_dns_query(1, "a..b").is_none());
    // a response: the question, then www.example.com CNAME host.example.com (the target is "host" plus a pointer to the
    // question's "example.com"), then host.example.com A 93.184.216.34 (its owner is a pointer to the CNAME's data)
    let mut r = Vec::new();
    r.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
    r.extend_from_slice(&q[12..]); // 3www7example3com0 + type + class: offsets 12..33
    assert_eq!(r.len(), 33);
    r.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 7, 4, b'h', b'o', b's', b't', 0xC0, 16]);
    r.extend_from_slice(&[0xC0, 45, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
    let a = parse_dns_response(&r).unwrap();
    assert_eq!((a.id, a.rcode, a.question.as_str(), &a.addrs[..]), (0x1234, 0, "www.example.com", &[[93, 184, 216, 34]][..]));
    // an answer for some other name is not an answer
    let mut other = r.clone();
    other[34] = 16; // the CNAME's owner is now a pointer to "example.com"
    assert!(parse_dns_response(&other).unwrap().addrs.is_empty());
    // a response that loops through compression pointers is refused, not followed for ever
    let mut loopy = std::vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1];
    assert!(parse_dns_response(&loopy).is_none());
    loopy.truncate(14);
    assert!(parse_dns_response(&loopy).is_none());
}

// ---- a simulated link ---------------------------------------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, per_mille: u64) -> bool {
        self.next() % 1000 < per_mille
    }
}

#[derive(Clone, Copy)]
struct LinkCfg {
    loss: u64,      // per mille
    dup: u64,       // per mille
    reorder: u64,   // per mille: extra delay up to 3x
    delay_ms: u64,  // one way
    bytes_per_ms: usize, // 0 = unlimited
}

const CLEAN: LinkCfg = LinkCfg { loss: 0, dup: 0, reorder: 0, delay_ms: 1, bytes_per_ms: 0 };

struct Net {
    a: Stack,
    b: Stack,
    now: u64,
    cfg: LinkCfg,
    rng: Rng,
    to_a: Vec<(u64, Vec<u8>)>,
    to_b: Vec<(u64, Vec<u8>)>,
    /// Bytes of data frames dropped, for assertions that loss really happened.
    dropped: usize,
    frames: usize,
    /// If set, frames in this direction are discarded (a dead peer).
    cut: bool,
    busy_until_a: u64,
    busy_until_b: u64,
}

const IP_A: Ip = [10, 0, 0, 1];
const IP_B: Ip = [10, 0, 0, 2];

impl Net {
    fn new(cfg: LinkCfg, seed: u64) -> Net {
        let mut a = Stack::new([2, 0, 0, 0, 0, 1], seed);
        let mut b = Stack::new([2, 0, 0, 0, 0, 2], seed ^ 0x55);
        a.set_static(IpConfig { addr: IP_A, mask: [255, 255, 255, 0], gateway: None, dns: Vec::new() });
        b.set_static(IpConfig { addr: IP_B, mask: [255, 255, 255, 0], gateway: None, dns: Vec::new() });
        Net { a, b, now: 1000, cfg, rng: Rng(seed | 1), to_a: Vec::new(), to_b: Vec::new(), dropped: 0, frames: 0, cut: false, busy_until_a: 0, busy_until_b: 0 }
    }

    fn transmit(rng: &mut Rng, cfg: LinkCfg, now: u64, busy: &mut u64, queue: &mut Vec<(u64, Vec<u8>)>, f: Vec<u8>, dropped: &mut usize) {
        if rng.chance(cfg.loss) {
            *dropped += f.len();
            return;
        }
        let mut at = now + cfg.delay_ms;
        if cfg.bytes_per_ms > 0 {
            let start = (*busy).max(now);
            *busy = start + (f.len() / cfg.bytes_per_ms) as u64 + 1;
            at = *busy + cfg.delay_ms;
        }
        if rng.chance(cfg.reorder) {
            at += rng.next() % (3 * cfg.delay_ms + 3);
        }
        if rng.chance(cfg.dup) {
            queue.push((at + 1, f.clone()));
        }
        queue.push((at, f));
    }

    /// Advance one millisecond.
    fn tick(&mut self) {
        self.now += 1;
        let now = self.now;
        self.a.poll(now);
        self.b.poll(now);
        while let Some(f) = self.a.pop_tx() {
            self.frames += 1;
            if !self.cut {
                Net::transmit(&mut self.rng, self.cfg, now, &mut self.busy_until_a, &mut self.to_b, f, &mut self.dropped);
            }
        }
        while let Some(f) = self.b.pop_tx() {
            self.frames += 1;
            if !self.cut {
                Net::transmit(&mut self.rng, self.cfg, now, &mut self.busy_until_b, &mut self.to_a, f, &mut self.dropped);
            }
        }
        let due = |q: &mut Vec<(u64, Vec<u8>)>| {
            let mut d = Vec::new();
            let mut i = 0;
            while i < q.len() {
                if q[i].0 <= now {
                    d.push(q.remove(i).1);
                } else {
                    i += 1;
                }
            }
            d
        };
        for f in due(&mut self.to_a) {
            self.a.rx(&f, now);
        }
        for f in due(&mut self.to_b) {
            self.b.rx(&f, now);
        }
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.tick();
        }
    }

    fn until(&mut self, limit_ms: u64, mut cond: impl FnMut(&mut Net) -> bool) -> bool {
        for _ in 0..limit_ms {
            if cond(self) {
                return true;
            }
            self.tick();
        }
        cond(self)
    }
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u32).wrapping_mul(2654435761).wrapping_add(seed as u32).to_le_bytes()[2]).collect()
}

#[test]
fn arp_and_ping() {
    let mut n = Net::new(CLEAN, 1);
    let now = n.now;
    n.a.ping(IP_B, 7, 1, b"abcdefgh", now).unwrap();
    assert!(n.until(2000, |n| n.a.ping_reply().map(|r| assert_eq!((r.from, r.ident, r.seq, r.data), (IP_B, 7, 1, b"abcdefgh".to_vec()))).is_some()));
    // the next one needs no ARP round trip
    let before = n.frames;
    let now = n.now;
    n.a.ping(IP_B, 7, 2, b"x", now).unwrap();
    assert!(n.until(100, |n| n.a.ping_reply().is_some()));
    assert_eq!(n.frames - before, 2);
}

#[test]
fn ping_to_nobody_gives_up_quietly() {
    let mut n = Net::new(CLEAN, 2);
    let now = n.now;
    n.a.ping([10, 0, 0, 99], 1, 1, b"?", now).unwrap();
    n.run(10_000);
    assert!(n.a.ping_reply().is_none());
    assert!(n.a.next_timer().is_none(), "no timers left running for an address that never answered");
}

#[test]
fn udp_echo_and_port_unreachable() {
    let mut n = Net::new(CLEAN, 3);
    let sb = n.b.udp_bind(7).unwrap();
    let sa = n.a.udp_bind(0).unwrap();
    let pa = n.a.udp_port(sa).unwrap();
    assert!(pa >= 49152);
    let now = n.now;
    n.a.udp_send(sa, IP_B, 7, b"ping", now).unwrap();
    assert!(n.until(1000, |n| n.b.udp_recv(sb).unwrap().map(|(ip, port, d)| {
        assert_eq!((ip, port, d.as_slice()), (IP_A, pa, &b"ping"[..]));
        let now = n.now;
        n.b.udp_send(sb, ip, port, b"pong", now).unwrap();
    }).is_some()));
    assert!(n.until(1000, |n| n.a.udp_recv(sa).unwrap().is_some_and(|(_, _, d)| d == b"pong")));
    assert_eq!(n.a.udp_bind(pa), Err(NetError::InUse));
    // a datagram to a port nobody has produces no socket state, only an ICMP error that is ignored
    let now = n.now;
    n.a.udp_send(sa, IP_B, 9999, b"?", now).unwrap();
    n.run(100);
    assert!(n.a.udp_recv(sa).unwrap().is_none());
    assert_eq!(n.a.udp_send(sa, IP_B, 7, &[0; 1600], now), Err(NetError::TooBig));
    n.a.udp_close(sa);
    assert_eq!(n.a.udp_recv(sa), Err(NetError::BadHandle));
}

#[test]
fn fragmented_datagram_is_reassembled() {
    let mut n = Net::new(CLEAN, 4);
    let sb = n.b.udp_bind(5000).unwrap();
    let data = pattern(3000, 1);
    let udp = build_udp(IP_A, IP_B, 1234, 5000, &data);
    // three fragments, out of order; A's MAC is known to B after one ARP exchange
    let now = n.now;
    n.a.ping(IP_B, 1, 1, b"", now).unwrap();
    n.run(50);
    let mk = |off: usize, len: usize, more: bool| {
        let mut p = build_ipv4(IP_A, IP_B, PROTO_UDP, 99, 64, &udp[off..off + len]);
        let ff = (if more { 0x2000u16 } else { 0 }) | (off / 8) as u16;
        p[6..8].copy_from_slice(&ff.to_be_bytes());
        p[10..12].copy_from_slice(&[0, 0]);
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        build_eth(n.b.mac, n.a.mac, ETH_IPV4, &p)
    };
    let total = udp.len();
    let f = [mk(0, 1480, true), mk(1480, 1480, true), mk(2960, total - 2960, false)];
    let now = n.now;
    n.b.rx(&f[2], now);
    n.b.rx(&f[0], now);
    assert!(n.b.udp_recv(sb).unwrap().is_none());
    n.b.rx(&f[1], now);
    let (ip, port, d) = n.b.udp_recv(sb).unwrap().expect("reassembled");
    assert_eq!((ip, port), (IP_A, 1234));
    assert_eq!(d, data);
}

// ---- TCP ----------------------------------------------------------------------------------------------------------------------------

/// Move `data` from a to b through a connection, with b reading as fast as it likes; returns what b read.
fn transfer(n: &mut Net, from_a: usize, to_b: usize, data: &[u8], limit_ms: u64) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = std::vec![0u8; 8192];
    n.until(limit_ms, |n| {
        let now = n.now;
        if sent < data.len() {
            sent += n.a.tcp_write(from_a, &data[sent..], now).unwrap();
        }
        loop {
            match n.b.tcp_read(to_b, &mut buf, now).unwrap() {
                Io::Data(k) => got.extend_from_slice(&buf[..k]),
                _ => break,
            }
        }
        got.len() >= data.len()
    });
    got
}

/// ... and from b to a.
fn transfer_ba(n: &mut Net, from_b: usize, to_a: usize, data: &[u8], limit_ms: u64) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = std::vec![0u8; 8192];
    n.until(limit_ms, |n| {
        let now = n.now;
        if sent < data.len() {
            sent += n.b.tcp_write(from_b, &data[sent..], now).unwrap();
        }
        while let Io::Data(k) = n.a.tcp_read(to_a, &mut buf, now).unwrap() {
            got.extend_from_slice(&buf[..k]);
        }
        got.len() >= data.len()
    });
    got
}

fn connect(n: &mut Net, port: u16) -> (usize, usize, usize) {
    let l = n.b.tcp_listen(port, 4).unwrap();
    let now = n.now;
    let c = n.a.tcp_connect(IP_B, port, now).unwrap();
    let mut s = None;
    assert!(n.until(20_000, |n| {
        s = s.or_else(|| n.b.tcp_accept(l));
        s.is_some() && n.a.tcp_state(c) == Some(State::Established)
    }), "handshake: a is {:?}", n.a.tcp_state(c));
    (c, s.unwrap(), l)
}

#[test]
fn handshake_and_orderly_close() {
    let mut n = Net::new(CLEAN, 5);
    let (c, s, _l) = connect(&mut n, 80);
    assert_eq!(n.b.tcp_peer(s).map(|p| p.0), Some(IP_A));
    assert_eq!(transfer(&mut n, c, s, b"GET / HTTP/1.0\r\n\r\n", 1000), b"GET / HTTP/1.0\r\n\r\n");
    let got = transfer_ba(&mut n, s, c, b"HTTP/1.0 200 OK\r\n\r\nhi", 1000);
    assert_eq!(got, b"HTTP/1.0 200 OK\r\n\r\nhi");
    // the server closes first; the client sees the end after reading everything
    let now = n.now;
    n.b.tcp_close(s, now);
    assert!(n.until(2000, |n| n.a.tcp_state(c) == Some(State::CloseWait)));
    let mut buf = [0u8; 10];
    let now = n.now;
    assert_eq!(n.a.tcp_read(c, &mut buf, now), Ok(Io::Eof));
    n.a.tcp_close(c, now);
    assert!(n.until(2000, |n| n.a.tcp_state(c).is_none_or(|s| s == State::Closed) || n.a.tcp_state(c) == Some(State::Closed)));
    assert_eq!(n.b.tcp_state(s), Some(State::TimeWait));
    n.a.tcp_release(c, n.now);
    n.b.tcp_release(s, n.now);
    n.run(tcp::MSL_MS * 2 + 500);
    assert_eq!(n.a.connection_count() + n.b.connection_count(), 0, "everything is freed after TIME-WAIT");
}

#[test]
fn bulk_transfer_clean_link() {
    let mut n = Net::new(LinkCfg { delay_ms: 5, bytes_per_ms: 1250, ..CLEAN }, 6); // 10 Mbit/s, 10 ms RTT
    let (c, s, _) = connect(&mut n, 5001);
    let data = pattern(1_000_000, 3);
    let t0 = n.now;
    let got = transfer(&mut n, c, s, &data, 60_000);
    assert_eq!(got.len(), data.len());
    assert!(got == data);
    let ms = n.now - t0;
    // 1 MB at 1250 B/ms is 800 ms of wire time; congestion control and acks may double that, not more than 3x
    assert!(ms < 2400, "took {ms} ms");
}

#[test]
fn both_directions_at_once() {
    let mut n = Net::new(LinkCfg { delay_ms: 3, ..CLEAN }, 7);
    let (c, s, _) = connect(&mut n, 5002);
    let (d1, d2) = (pattern(300_000, 1), pattern(200_000, 2));
    let (mut s1, mut s2) = (0, 0);
    let (mut g1, mut g2) = (Vec::new(), Vec::new());
    let mut buf = std::vec![0u8; 4096];
    assert!(n.until(60_000, |n| {
        let now = n.now;
        if s1 < d1.len() {
            s1 += n.a.tcp_write(c, &d1[s1..], now).unwrap();
        }
        if s2 < d2.len() {
            s2 += n.b.tcp_write(s, &d2[s2..], now).unwrap();
        }
        if let Ok(Io::Data(k)) = n.b.tcp_read(s, &mut buf, now) {
            g1.extend_from_slice(&buf[..k]);
        }
        if let Ok(Io::Data(k)) = n.a.tcp_read(c, &mut buf, now) {
            g2.extend_from_slice(&buf[..k]);
        }
        g1.len() == d1.len() && g2.len() == d2.len()
    }));
    assert!(g1 == d1 && g2 == d2);
}

fn lossy(loss: u64, dup: u64, reorder: u64, seed: u64, size: usize) {
    let mut n = Net::new(LinkCfg { loss, dup, reorder, delay_ms: 10, bytes_per_ms: 2500 }, seed);
    let (c, s, _) = connect(&mut n, 5003);
    let data = pattern(size, seed as u8);
    let got = transfer(&mut n, c, s, &data, 600_000);
    assert!(got.len() == data.len(), "seed {seed}: {} of {} bytes arrived (loss {loss}, dup {dup}, reorder {reorder})\nsender:   {}\nreceiver: {}", got.len(), data.len(), n.a.tcp_summary(c), n.b.tcp_summary(s));
    assert!(got == data, "seed {seed}: data differs");
    if loss >= 20 {
        assert!(n.dropped > 0);
    }
}

#[test]
fn transfer_with_loss() {
    for seed in 1..=4 {
        lossy(20, 0, 0, seed, 300_000); // 2 %
    }
    lossy(100, 0, 0, 9, 100_000); // 10 %
}

#[test]
fn transfer_with_reordering_and_duplicates() {
    for seed in 1..=3 {
        lossy(0, 0, 200, seed, 300_000);
        lossy(0, 150, 0, seed + 10, 200_000);
        lossy(10, 50, 100, seed + 20, 200_000);
    }
}

#[test]
fn connecting_to_a_closed_port_is_refused() {
    let mut n = Net::new(CLEAN, 8);
    let now = n.now;
    let c = n.a.tcp_connect(IP_B, 9, now).unwrap();
    assert!(n.until(5000, |n| n.a.tcp_state(c) == Some(State::Closed)));
    assert_eq!(n.a.tcp_error(c), Some(tcp::Error::Refused));
}

#[test]
fn connecting_to_nobody_times_out() {
    let mut n = Net::new(CLEAN, 9);
    n.cut = true;
    let now = n.now;
    let c = n.a.tcp_connect(IP_B, 80, now).unwrap();
    assert!(n.until(200_000, |n| n.a.tcp_state(c) == Some(State::Closed)));
    assert_eq!(n.a.tcp_error(c), Some(tcp::Error::TimedOut));
}

#[test]
fn syn_is_retransmitted_through_loss() {
    let mut n = Net::new(LinkCfg { loss: 500, ..CLEAN }, 10);
    let (c, s, _) = connect(&mut n, 8080);
    assert_eq!(transfer(&mut n, c, s, b"x", 60_000), b"x");
}

#[test]
fn established_connection_to_a_vanished_peer_times_out() {
    let mut n = Net::new(CLEAN, 11);
    let (c, _s, _) = connect(&mut n, 7000);
    n.cut = true;
    let now = n.now;
    n.a.tcp_write(c, b"anybody?", now).unwrap();
    assert!(n.until(2_000_000, |n| n.a.tcp_state(c) == Some(State::Closed)));
    assert_eq!(n.a.tcp_error(c), Some(tcp::Error::TimedOut));
}

#[test]
fn abort_resets_the_peer() {
    let mut n = Net::new(CLEAN, 12);
    let (c, s, _) = connect(&mut n, 7001);
    let now = n.now;
    n.a.tcp_abort(c, now);
    assert!(n.until(1000, |n| n.b.tcp_state(s) == Some(State::Closed)));
    assert_eq!(n.b.tcp_error(s), Some(tcp::Error::Reset));
    let mut buf = [0u8; 4];
    assert_eq!(n.b.tcp_read(s, &mut buf, n.now), Ok(Io::Failed(tcp::Error::Reset)));
}

#[test]
fn half_close_still_receives() {
    let mut n = Net::new(CLEAN, 13);
    let (c, s, _) = connect(&mut n, 7002);
    transfer(&mut n, c, s, b"request", 1000);
    let now = n.now;
    n.a.tcp_close(c, now); // the client is done sending
    assert!(n.until(1000, |n| n.b.tcp_state(s) == Some(State::CloseWait)));
    assert_eq!(n.b.tcp_read(s, &mut [0u8; 1], n.now), Ok(Io::Eof));
    // ... the server can still answer
    let got = transfer_ba(&mut n, s, c, &pattern(50_000, 4), 20_000);
    assert_eq!(got.len(), 50_000);
    let now = n.now;
    n.b.tcp_close(s, now);
    assert!(n.until(5000, |n| n.a.tcp_state(c) == Some(State::TimeWait)));
}

#[test]
fn simultaneous_close() {
    let mut n = Net::new(LinkCfg { delay_ms: 20, ..CLEAN }, 14);
    let (c, s, _) = connect(&mut n, 7003);
    let now = n.now;
    n.a.tcp_close(c, now);
    n.b.tcp_close(s, now);
    assert!(n.until(5000, |n| n.a.tcp_state(c) == Some(State::TimeWait) && n.b.tcp_state(s) == Some(State::TimeWait)));
    n.run(tcp::MSL_MS * 2 + 200);
    assert_eq!(n.a.tcp_state(c), Some(State::Closed));
}

#[test]
fn a_slow_reader_throttles_the_writer_without_loss() {
    let mut n = Net::new(LinkCfg { delay_ms: 2, ..CLEAN }, 15);
    let (c, s, _) = connect(&mut n, 7004);
    let data = pattern(500_000, 5);
    let (mut sent, mut got) = (0, Vec::new());
    let mut buf = [0u8; 1000];
    let mut zero_window_seen = false;
    assert!(n.until(600_000, |n| {
        let now = n.now;
        if sent < data.len() {
            sent += n.a.tcp_write(c, &data[sent..], now).unwrap();
        }
        // the reader takes 1000 bytes every 10 ms: 100 kB/s
        if n.now % 10 == 0 {
            if let Ok(Io::Data(k)) = n.b.tcp_read(s, &mut buf, now) {
                got.extend_from_slice(&buf[..k]);
            }
        }
        zero_window_seen |= n.b.tcp_ready(s).unwrap().0 >= 60_000;
        got.len() == data.len()
    }));
    assert!(got == data);
    assert!(zero_window_seen, "the receive buffer really filled up");
}

#[test]
fn many_connections_and_the_backlog() {
    let mut n = Net::new(CLEAN, 16);
    let l = n.b.tcp_listen(9000, 2).unwrap();
    let mut conns = Vec::new();
    for _ in 0..5 {
        let now = n.now;
        conns.push(n.a.tcp_connect(IP_B, 9000, now).unwrap());
        n.run(30);
    }
    // two fit the backlog; the others keep retrying their SYN until someone accepts
    n.run(200);
    let est = conns.iter().filter(|&&c| n.a.tcp_state(c) == Some(State::Established)).count();
    assert_eq!(est, 2);
    let mut accepted = 0;
    n.until(30_000, |n| {
        while n.b.tcp_accept(l).is_some() {
            accepted += 1;
        }
        accepted == 5
    });
    assert_eq!(accepted, 5);
    // a listener that goes away resets what was never accepted
    n.b.tcp_unlisten(l);
    let now = n.now;
    let c = n.a.tcp_connect(IP_B, 9000, now).unwrap();
    assert!(n.until(5000, |n| n.a.tcp_state(c) == Some(State::Closed)));
    assert_eq!(n.a.tcp_error(c), Some(tcp::Error::Refused));
}

#[test]
fn nagle_batches_small_writes_and_nodelay_does_not() {
    for nodelay in [false, true] {
        let mut n = Net::new(LinkCfg { delay_ms: 20, ..CLEAN }, 17);
        let (c, s, _) = connect(&mut n, 7005);
        n.a.tcp_set_nodelay(c, nodelay);
        let before = n.frames;
        for i in 0..20u8 {
            let now = n.now;
            n.a.tcp_write(c, &[i], now).unwrap();
            n.tick();
        }
        n.run(500);
        let data_frames = n.frames - before;
        let mut buf = [0u8; 100];
        let r = n.b.tcp_read(s, &mut buf, n.now);
        assert_eq!(r, Ok(Io::Data(20)));
        if nodelay {
            assert!(data_frames >= 20, "{data_frames}");
        } else {
            assert!(data_frames < 20, "{data_frames}");
        }
    }
}

#[test]
fn a_blind_rst_outside_the_exact_sequence_does_not_kill_the_connection() {
    let mut n = Net::new(CLEAN, 18);
    let (c, s, _) = connect(&mut n, 7006);
    transfer(&mut n, c, s, b"hi", 500);
    let (src, dst) = (n.a.tcp_peer(c).unwrap(), (IP_A, 0));
    let _ = (src, dst);
    // craft a RST from A to B with a sequence number inside the window but not exact: needs A's real port and seq
    let port_a = n.b.tcp_peer(s).unwrap().1;
    let (mac_a, mac_b) = (n.a.mac, n.b.mac);
    let rst = move |seq: u32| {
        let seg = build_tcp(IP_A, IP_B, &TcpOut { src_port: port_a, dst_port: 7006, seq, ack: 0, flags: RST, window: 0, mss: None, window_scale: None, payload: b"" });
        build_eth(mac_b, mac_a, ETH_IPV4, &build_ipv4(IP_A, IP_B, PROTO_TCP, 1, 64, &seg))
    };
    // learn A's current sequence number from the next segment B receives (once the earlier data is acknowledged, so
    // that Nagle's algorithm lets a one-byte segment out at once)
    n.run(200);
    let now = n.now;
    n.a.tcp_write(c, b"x", now).unwrap();
    let mut seen = 0;
    let mut hold = Vec::new();
    while let Some(f) = n.a.pop_tx() {
        hold.push(f);
    }
    for f in &hold {
        let eth = Eth::parse(f).unwrap();
        if eth.ethertype == ETH_IPV4 {
            let ip = Ipv4::parse(eth.payload).unwrap();
            if ip.proto == PROTO_TCP {
                seen = Tcp::parse(ip.src, ip.dst, ip.payload).unwrap().seq;
            }
        }
    }
    let now = n.now;
    for f in &hold {
        n.b.rx(f, now);
    }
    // the real next sequence number is seen + 1; a reset one off from it only provokes an ACK
    n.b.rx(&rst(seen.wrapping_add(5)), now);
    assert_eq!(n.b.tcp_state(s), Some(State::Established));
    n.b.rx(&rst(seen.wrapping_add(1)), now);
    assert_eq!(n.b.tcp_state(s), Some(State::Closed));
}

// ---- DHCP and DNS --------------------------------------------------------------------------------------------------------------------

#[test]
fn dhcp_acquires_renews_and_loses_a_lease() {
    let mut n = Net::new(CLEAN, 19);
    n.a = Stack::new([2, 0, 0, 0, 0, 1], 5);
    let server = n.b.udp_bind(DHCP_SERVER_PORT).unwrap();
    n.b.set_static(IpConfig { addr: [10, 0, 0, 2], mask: [255, 255, 255, 0], gateway: None, dns: Vec::new() });
    n.a.start_dhcp(n.now);
    let offered = std::cell::Cell::new(0u32);
    let acked = std::cell::Cell::new(0u32);
    let nak = std::cell::Cell::new(false);
    let lease = 60;
    let answer = |n: &mut Net| {
        while let Some((_, _, d)) = n.b.udp_recv(server).unwrap() {
            let m = Dhcp::parse(&d).unwrap();
            let reply = |t: u8| Dhcp { op: 2, xid: m.xid, yiaddr: [10, 0, 0, 77], chaddr: m.chaddr, msg_type: t, subnet_mask: Some([255, 255, 255, 0]), router: Some([10, 0, 0, 2]), dns: std::vec![[10, 0, 0, 2]], lease_secs: Some(lease), server_id: Some([10, 0, 0, 2]), requested_ip: None };
            let (t, count) = match m.msg_type {
                DHCP_DISCOVER => (DHCP_OFFER, &offered),
                _ if nak.get() => (DHCP_NAK, &acked),
                _ => (DHCP_ACK, &acked),
            };
            count.set(count.get() + 1);
            // the reply is broadcast (the client has no address yet), built by hand
            let udp = build_udp([10, 0, 0, 2], BROADCAST_IP, DHCP_SERVER_PORT, DHCP_CLIENT_PORT, &reply(t).build());
            let ip = build_ipv4([10, 0, 0, 2], BROADCAST_IP, PROTO_UDP, 5, 64, &udp);
            let f = build_eth(BROADCAST_MAC, n.b.mac, ETH_IPV4, &ip);
            let now = n.now;
            n.a.rx(&f, now);
        }
    };
    assert!(n.until(20_000, |n| {
        answer(n);
        n.a.dhcp_bound()
    }));
    let c = n.a.config().unwrap().clone();
    assert_eq!((c.addr, c.mask, c.gateway, c.dns), ([10, 0, 0, 77], [255, 255, 255, 0], Some([10, 0, 0, 2]), std::vec![[10, 0, 0, 2]]));
    assert_eq!((offered.get(), acked.get()), (1, 1));
    // half the lease later it asks again, and keeps its address
    assert!(n.until(40_000, |n| {
        answer(n);
        acked.get() >= 2
    }), "{} now={}", n.a.dhcp_debug(), n.now);
    assert!(n.a.config().is_some());
    // a refusal takes the address away and starts over
    nak.set(true);
    assert!(n.until(80_000, |n| {
        answer(n);
        n.a.config().is_none()
    }));
    nak.set(false);
    assert!(n.until(60_000, |n| {
        answer(n);
        n.a.config().is_some()
    }));
}

#[test]
fn dns_resolution_with_retries() {
    let mut n = Net::new(CLEAN, 20);
    n.a.set_static(IpConfig { addr: IP_A, mask: [255, 255, 255, 0], gateway: None, dns: std::vec![IP_B] });
    let server = n.b.udp_bind(DNS_PORT).unwrap();
    let now = n.now;
    let q = n.a.dns_start("example.test", now).unwrap();
    let seen = std::cell::Cell::new(0u32);
    let answer = |n: &mut Net, drop_first: bool| {
        while let Some((ip, port, d)) = n.b.udp_recv(server).unwrap() {
            seen.set(seen.get() + 1);
            if drop_first && seen.get() == 1 {
                continue; // the first query is lost: the resolver asks again
            }
            let mut r = d.clone();
            r[2] = 0x81;
            r[3] = 0x80;
            r[7] = 1; // one answer
            r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
            let now = n.now;
            n.b.udp_send(server, ip, port, &r, now).unwrap();
        }
    };
    assert!(n.until(10_000, |n| {
        answer(n, true);
        n.a.dns_result(q) != DnsResult::Pending
    }));
    assert_eq!(n.a.dns_result(q), DnsResult::Addrs(std::vec![[192, 0, 2, 7]]));
    assert!(seen.get() >= 2);
    n.a.dns_release(q);
    // a name with no servers fails quickly instead of waiting for ever
    n.a.set_static(IpConfig { addr: IP_A, mask: [255, 255, 255, 0], gateway: None, dns: Vec::new() });
    let now = n.now;
    let q = n.a.dns_start("nothing.test", now).unwrap();
    assert_eq!(n.a.dns_result(q), DnsResult::Failed);
}

// ---- robustness ----------------------------------------------------------------------------------------------------------------------

#[test]
fn garbage_frames_never_panic() {
    let mut n = Net::new(CLEAN, 21);
    let (c, s, _) = connect(&mut n, 6000);
    transfer(&mut n, c, s, &pattern(10_000, 1), 5000);
    let sock = n.b.udp_bind(53).unwrap();
    let mut rng = Rng(0x1234_5678_9ABC);
    // seeds: a real TCP data segment, a real ARP, a real UDP, a real ICMP, mutated and truncated at random
    let now = n.now;
    n.a.tcp_write(c, b"payload", now).unwrap();
    n.tick();
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    while let Some(f) = n.a.pop_tx() {
        seeds.push(f);
    }
    seeds.push(build_eth(n.b.mac, n.a.mac, ETH_IPV4, &build_ipv4(IP_A, IP_B, PROTO_UDP, 3, 64, &build_udp(IP_A, IP_B, 99, 53, b"abc"))));
    seeds.push(build_eth(n.b.mac, n.a.mac, ETH_IPV4, &build_ipv4(IP_A, IP_B, PROTO_ICMP, 3, 64, &build_icmp(8, 0, [0, 1, 0, 1], b"data"))));
    seeds.push(build_eth(BROADCAST_MAC, n.a.mac, ETH_ARP, &Arp { op: ARP_REQUEST, sha: n.a.mac, spa: IP_A, tha: [0; 6], tpa: IP_B }.build()));
    for i in 0..200_000 {
        let mut f = seeds[i % seeds.len()].clone();
        for _ in 0..1 + rng.next() % 4 {
            let at = (rng.next() as usize) % f.len();
            f[at] = rng.next() as u8;
        }
        if rng.next() % 5 == 0 {
            let l = (rng.next() as usize) % f.len();
            f.truncate(l);
        }
        let now = n.now + (i as u64 / 100);
        n.b.rx(&f, now);
        if i % 1000 == 0 {
            n.b.poll(now);
            while n.b.pop_tx().is_some() {}
            while n.b.udp_recv(sock).unwrap().is_some() {}
        }
    }
    // pure noise
    for _ in 0..50_000 {
        let l = (rng.next() % 200) as usize;
        let f: Vec<u8> = (0..l).map(|_| rng.next() as u8).collect();
        n.b.rx(&f, n.now);
    }
}

/// Random segments with plausible sequence numbers thrown at an established connection: it must stay in a consistent
/// state (no panic, no impossible buffer sizes), and an honest peer's data must still get through afterwards when the
/// connection survived.
#[test]
fn random_segments_keep_the_state_machine_sane() {
    for seed in 1..=40u64 {
        let mut n = Net::new(CLEAN, 100 + seed);
        let (c, s, _) = connect(&mut n, 6001);
        let mut rng = Rng(seed * 7919);
        let port_a = n.b.tcp_peer(s).unwrap().1;
        let now = n.now;
        n.a.tcp_write(c, &pattern(5000, 1), now).unwrap();
        n.run(50);
        for _ in 0..300 {
            let flags = [ACK, ACK | PSH, ACK | FIN, SYN, SYN | ACK, RST, RST | ACK, ACK, ACK | PSH][(rng.next() % 9) as usize];
            let base = 0x1000_0000u32; // anywhere near the real numbers is unlikely; mix in wild values
            let seq = if rng.chance(500) { rng.next() as u32 } else { base.wrapping_add((rng.next() % 3000) as u32) };
            let len = (rng.next() % 1500) as usize;
            let payload = pattern(len, rng.next() as u8);
            let seg = build_tcp(IP_A, IP_B, &TcpOut { src_port: port_a, dst_port: 6001, seq, ack: rng.next() as u32, flags, window: rng.next() as u16, mss: None, window_scale: None, payload: &payload });
            let f = build_eth(n.b.mac, n.a.mac, ETH_IPV4, &build_ipv4(IP_A, IP_B, PROTO_TCP, 1, 64, &seg));
            let now = n.now;
            n.b.rx(&f, now);
            n.tick();
            let mut buf = [0u8; 2000];
            let _ = n.b.tcp_read(s, &mut buf, n.now);
            if let Some((r, w)) = n.b.tcp_ready(s) {
                assert!(r <= 64 * 1024 && w <= 64 * 1024);
            }
        }
        n.run(2000);
    }
}

const SOAK_SEED: u64 = 0x9e37_79b9;
const SOAK_ROUNDS: u64 = 100;

/// Many random links and transfer sizes, both directions, ending in an orderly close from a random side.
#[test]
fn soak_random_links() {
    let mut rng = Rng(0xFEED_FACE ^ SOAK_SEED);
    for round in 0..SOAK_ROUNDS {
        let cfg = LinkCfg { loss: rng.next() % 60, dup: rng.next() % 80, reorder: rng.next() % 250, delay_ms: 1 + rng.next() % 40, bytes_per_ms: [0, 500, 1250, 5000][(rng.next() % 4) as usize] };
        let mut n = Net::new(cfg, 1000 + round);
        let (c, s, _) = connect(&mut n, 6500);
        let (d1, d2) = (pattern(20_000 + (rng.next() % 150_000) as usize, round as u8), pattern((rng.next() % 100_000) as usize, 99));
        let (mut s1, mut s2) = (0, 0);
        let (mut g1, mut g2) = (Vec::new(), Vec::new());
        let mut buf = std::vec![0u8; 3000];
        let ok = n.until(1_500_000, |n| {
            let now = n.now;
            if s1 < d1.len() {
                s1 += n.a.tcp_write(c, &d1[s1..], now).unwrap();
            }
            if s2 < d2.len() {
                s2 += n.b.tcp_write(s, &d2[s2..], now).unwrap();
            }
            if let Ok(Io::Data(k)) = n.b.tcp_read(s, &mut buf, now) {
                g1.extend_from_slice(&buf[..k]);
            }
            if let Ok(Io::Data(k)) = n.a.tcp_read(c, &mut buf, now) {
                g2.extend_from_slice(&buf[..k]);
            }
            g1.len() == d1.len() && g2.len() == d2.len()
        });
        assert!(ok, "round {round} {:?}: {} of {} and {} of {}\nA: {}\nB: {}", (cfg.loss, cfg.dup, cfg.reorder, cfg.delay_ms, cfg.bytes_per_ms), g1.len(), d1.len(), g2.len(), d2.len(), n.a.tcp_summary(c), n.b.tcp_summary(s));
        assert!(g1 == d1 && g2 == d2, "round {round}: data differs");
        let now = n.now;
        if round % 2 == 0 {
            n.a.tcp_close(c, now);
            n.b.tcp_close(s, now);
        } else {
            n.b.tcp_close(s, now);
            assert!(n.until(60_000, |n| n.a.tcp_state(c) == Some(State::CloseWait)), "round {round}: FIN lost for good");
            let now = n.now;
            n.a.tcp_close(c, now);
        }
        assert!(n.until(300_000, |n| matches!(n.a.tcp_state(c), Some(State::TimeWait | State::Closed)) && matches!(n.b.tcp_state(s), Some(State::TimeWait | State::Closed))), "round {round}: close: {} / {}", n.a.tcp_summary(c), n.b.tcp_summary(s));
    }
}
