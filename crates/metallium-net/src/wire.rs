//! Packet formats: building and parsing, nothing else. Written from RFC 826 (ARP), 791 (IPv4), 792 (ICMP), 768 (UDP),
//! 9293 (TCP), 1071 (the checksum), 2131/2132 (DHCP) and 1035 (DNS).
use alloc::vec::Vec;

pub type Mac = [u8; 6];
pub type Ip = [u8; 4];

pub const BROADCAST_MAC: Mac = [0xFF; 6];
pub const ANY_IP: Ip = [0; 4];
pub const BROADCAST_IP: Ip = [255; 4];

pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_ARP: u16 = 0x0806;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}
fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// One's-complement sum of 16-bit words (RFC 1071), not yet inverted. `init` continues a sum.
pub fn sum16(data: &[u8], init: u32) -> u32 {
    let mut s = init;
    let mut it = data.chunks_exact(2);
    for w in &mut it {
        s += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    if let [last] = it.remainder() {
        s += (*last as u32) << 8;
    }
    s
}

pub fn fold(mut s: u32) -> u16 {
    while s >> 16 != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    s as u16
}

/// The Internet checksum of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    !fold(sum16(data, 0))
}

/// The pseudo-header sum for UDP/TCP over IPv4.
pub fn pseudo_sum(src: Ip, dst: Ip, proto: u8, len: usize) -> u32 {
    sum16(&src, 0) + sum16(&dst, 0) + proto as u32 + len as u32
}

// ---- Ethernet ---------------------------------------------------------------------------------------------------------

pub struct Eth<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

impl<'a> Eth<'a> {
    pub fn parse(f: &'a [u8]) -> Option<Eth<'a>> {
        if f.len() < 14 {
            return None;
        }
        Some(Eth { dst: f[0..6].try_into().unwrap(), src: f[6..12].try_into().unwrap(), ethertype: be16(f, 12), payload: &f[14..] })
    }
}

pub fn build_eth(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len().max(46));
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    while f.len() < 60 {
        f.push(0); // the minimum frame (the checksum is the device's job)
    }
    f
}

// ---- ARP --------------------------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Arp {
    pub op: u16,
    pub sha: Mac,
    pub spa: Ip,
    pub tha: Mac,
    pub tpa: Ip,
}

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

impl Arp {
    pub fn parse(p: &[u8]) -> Option<Arp> {
        if p.len() < 28 || be16(p, 0) != 1 || be16(p, 2) != ETH_IPV4 || p[4] != 6 || p[5] != 4 {
            return None;
        }
        let op = be16(p, 6);
        if op != ARP_REQUEST && op != ARP_REPLY {
            return None;
        }
        Some(Arp { op, sha: p[8..14].try_into().unwrap(), spa: p[14..18].try_into().unwrap(), tha: p[18..24].try_into().unwrap(), tpa: p[24..28].try_into().unwrap() })
    }

    pub fn build(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&ETH_IPV4.to_be_bytes());
        p.extend_from_slice(&[6, 4]);
        p.extend_from_slice(&self.op.to_be_bytes());
        p.extend_from_slice(&self.sha);
        p.extend_from_slice(&self.spa);
        p.extend_from_slice(&self.tha);
        p.extend_from_slice(&self.tpa);
        p
    }
}

// ---- IPv4 -------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Ipv4<'a> {
    pub src: Ip,
    pub dst: Ip,
    pub proto: u8,
    pub ttl: u8,
    pub id: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// In bytes.
    pub frag_offset: usize,
    pub payload: &'a [u8],
}

impl<'a> Ipv4<'a> {
    /// Parse and check (version, header length, total length, header checksum). Trailing padding is cut off.
    pub fn parse(p: &'a [u8]) -> Option<Ipv4<'a>> {
        if p.len() < 20 || p[0] >> 4 != 4 {
            return None;
        }
        let ihl = (p[0] & 0xF) as usize * 4;
        let total = be16(p, 2) as usize;
        if ihl < 20 || total < ihl || total > p.len() || checksum(&p[..ihl]) != 0 {
            return None;
        }
        let ff = be16(p, 6);
        Some(Ipv4 {
            src: p[12..16].try_into().unwrap(),
            dst: p[16..20].try_into().unwrap(),
            proto: p[9],
            ttl: p[8],
            id: be16(p, 4),
            dont_fragment: ff & 0x4000 != 0,
            more_fragments: ff & 0x2000 != 0,
            frag_offset: (ff & 0x1FFF) as usize * 8,
            payload: &p[ihl..total],
        })
    }

    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.frag_offset != 0
    }
}

pub fn build_ipv4(src: Ip, dst: Ip, proto: u8, id: u16, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&[0x45, 0]);
    p.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment (we never fragment)
    p.push(ttl);
    p.push(proto);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

// ---- ICMP -------------------------------------------------------------------------------------------------------------

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_UNREACHABLE: u8 = 3;
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;

#[derive(Debug, Clone, Copy)]
pub struct Icmp<'a> {
    pub kind: u8,
    pub code: u8,
    /// The four bytes after the checksum (identifier+sequence for echo).
    pub rest: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> Icmp<'a> {
    pub fn parse(p: &'a [u8]) -> Option<Icmp<'a>> {
        if p.len() < 8 || checksum(p) != 0 {
            return None;
        }
        Some(Icmp { kind: p[0], code: p[1], rest: p[4..8].try_into().unwrap(), payload: &p[8..] })
    }
}

pub fn build_icmp(kind: u8, code: u8, rest: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&[kind, code, 0, 0]);
    p.extend_from_slice(&rest);
    p.extend_from_slice(payload);
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

// ---- UDP --------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> Udp<'a> {
    /// Parse; a zero checksum means "none" (RFC 768), anything else must verify.
    pub fn parse(src: Ip, dst: Ip, p: &'a [u8]) -> Option<Udp<'a>> {
        if p.len() < 8 {
            return None;
        }
        let len = be16(p, 4) as usize;
        if len < 8 || len > p.len() {
            return None;
        }
        let p = &p[..len];
        if be16(p, 6) != 0 && fold(sum16(p, pseudo_sum(src, dst, PROTO_UDP, len))) != 0xFFFF {
            return None;
        }
        Some(Udp { src_port: be16(p, 0), dst_port: be16(p, 2), payload: &p[8..] })
    }
}

pub fn build_udp(src: Ip, dst: Ip, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    let mut c = !fold(sum16(&p, pseudo_sum(src, dst, PROTO_UDP, len)));
    if c == 0 {
        c = 0xFFFF; // (zero means "no checksum")
    }
    p[6..8].copy_from_slice(&c.to_be_bytes());
    p
}

// ---- TCP --------------------------------------------------------------------------------------------------------------

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

impl<'a> Tcp<'a> {
    pub fn parse(src: Ip, dst: Ip, p: &'a [u8]) -> Option<Tcp<'a>> {
        if p.len() < 20 {
            return None;
        }
        let off = (p[12] >> 4) as usize * 4;
        if off < 20 || off > p.len() || fold(sum16(p, pseudo_sum(src, dst, PROTO_TCP, p.len()))) != 0xFFFF {
            return None;
        }
        let mut options = TcpOptions::default();
        let mut o = &p[20..off];
        while let Some(&kind) = o.first() {
            match kind {
                0 => break,
                1 => o = &o[1..],
                _ => {
                    let len = *o.get(1)? as usize;
                    if len < 2 || len > o.len() {
                        return None;
                    }
                    match (kind, len) {
                        (2, 4) => options.mss = Some(be16(o, 2)),
                        (3, 3) => options.window_scale = Some(o[2].min(14)),
                        _ => {}
                    }
                    o = &o[len..];
                }
            }
        }
        Some(Tcp { src_port: be16(p, 0), dst_port: be16(p, 2), seq: be32(p, 4), ack: be32(p, 8), flags: p[13] & 0x3F, window: be16(p, 14), options, payload: &p[off..] })
    }

    /// Sequence space this segment takes (data plus SYN and FIN).
    pub fn seq_len(&self) -> u32 {
        self.payload.len() as u32 + (self.flags & SYN != 0) as u32 + (self.flags & FIN != 0) as u32
    }
}

pub struct TcpOut<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub payload: &'a [u8],
}

pub fn build_tcp(src: Ip, dst: Ip, s: &TcpOut) -> Vec<u8> {
    let mut opts = Vec::new();
    if let Some(m) = s.mss {
        opts.extend_from_slice(&[2, 4]);
        opts.extend_from_slice(&m.to_be_bytes());
    }
    if let Some(w) = s.window_scale {
        opts.extend_from_slice(&[1, 3, 3, w]); // (a NOP first, to keep the option list a multiple of four)
    }
    let hlen = 20 + opts.len();
    let mut p = Vec::with_capacity(hlen + s.payload.len());
    p.extend_from_slice(&s.src_port.to_be_bytes());
    p.extend_from_slice(&s.dst_port.to_be_bytes());
    p.extend_from_slice(&s.seq.to_be_bytes());
    p.extend_from_slice(&s.ack.to_be_bytes());
    p.push((hlen / 4) as u8) ;
    p[12] <<= 4;
    p.push(s.flags);
    p.extend_from_slice(&s.window.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]);
    p.extend_from_slice(&opts);
    p.extend_from_slice(s.payload);
    let c = !fold(sum16(&p, pseudo_sum(src, dst, PROTO_TCP, p.len())));
    p[16..18].copy_from_slice(&c.to_be_bytes());
    p
}

// ---- DHCP -------------------------------------------------------------------------------------------------------------

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dhcp {
    pub op: u8,
    pub xid: u32,
    pub yiaddr: Ip,
    pub chaddr: Mac,
    pub msg_type: u8,
    pub subnet_mask: Option<Ip>,
    pub router: Option<Ip>,
    pub dns: Vec<Ip>,
    pub lease_secs: Option<u32>,
    pub server_id: Option<Ip>,
    pub requested_ip: Option<Ip>,
}

const MAGIC: [u8; 4] = [99, 130, 83, 99];

impl Dhcp {
    pub fn parse(p: &[u8]) -> Option<Dhcp> {
        if p.len() < 240 || p[236..240] != MAGIC {
            return None;
        }
        let mut d = Dhcp { op: p[0], xid: be32(p, 4), yiaddr: p[16..20].try_into().unwrap(), chaddr: p[28..34].try_into().unwrap(), ..Dhcp::default() };
        let mut o = &p[240..];
        while let Some(&kind) = o.first() {
            match kind {
                0 => o = &o[1..],
                255 => break,
                _ => {
                    let len = *o.get(1)? as usize;
                    let v = o.get(2..2 + len)?;
                    match (kind, len) {
                        (53, 1) => d.msg_type = v[0],
                        (1, 4) => d.subnet_mask = Some(v.try_into().unwrap()),
                        (3, l) if l >= 4 => d.router = Some(v[..4].try_into().unwrap()),
                        (6, l) if l >= 4 => d.dns = v.chunks_exact(4).map(|c| c.try_into().unwrap()).collect(),
                        (51, 4) => d.lease_secs = Some(be32(v, 0)),
                        (54, 4) => d.server_id = Some(v.try_into().unwrap()),
                        (50, 4) => d.requested_ip = Some(v.try_into().unwrap()),
                        _ => {}
                    }
                    o = &o[2 + len..];
                }
            }
        }
        (d.msg_type != 0).then_some(d)
    }

    pub fn build(&self) -> Vec<u8> {
        let mut p = alloc::vec![0u8; 240];
        p[0] = self.op;
        p[1] = 1; // Ethernet
        p[2] = 6;
        p[4..8].copy_from_slice(&self.xid.to_be_bytes());
        p[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // ask for a broadcast answer (we have no address yet)
        p[16..20].copy_from_slice(&self.yiaddr);
        p[28..34].copy_from_slice(&self.chaddr);
        p[236..240].copy_from_slice(&MAGIC);
        p.extend_from_slice(&[53, 1, self.msg_type]);
        if let Some(ip) = self.requested_ip {
            p.extend_from_slice(&[50, 4]);
            p.extend_from_slice(&ip);
        }
        if let Some(ip) = self.server_id {
            p.extend_from_slice(&[54, 4]);
            p.extend_from_slice(&ip);
        }
        if let Some(m) = self.subnet_mask {
            p.extend_from_slice(&[1, 4]);
            p.extend_from_slice(&m);
        }
        if let Some(r) = self.router {
            p.extend_from_slice(&[3, 4]);
            p.extend_from_slice(&r);
        }
        if !self.dns.is_empty() {
            p.extend_from_slice(&[6, (4 * self.dns.len()) as u8]);
            for d in &self.dns {
                p.extend_from_slice(d);
            }
        }
        if let Some(l) = self.lease_secs {
            p.extend_from_slice(&[51, 4]);
            p.extend_from_slice(&l.to_be_bytes());
        }
        if self.op == 1 {
            p.extend_from_slice(&[55, 3, 1, 3, 6]); // parameter request list: mask, router, DNS
        }
        p.push(255);
        p
    }
}

// ---- DNS --------------------------------------------------------------------------------------------------------------

pub const DNS_PORT: u16 = 53;
pub const DNS_A: u16 = 1;
pub const DNS_CNAME: u16 = 5;

pub fn build_dns_query(id: u16, name: &str) -> Option<Vec<u8>> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&DNS_A.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    (p.len() <= 512).then_some(p)
}

/// Skip a (possibly compressed) name starting at `o`; the offset after it.
fn skip_name(p: &[u8], mut o: usize) -> Option<usize> {
    loop {
        let l = *p.get(o)?;
        match l {
            0 => return Some(o + 1),
            l if l & 0xC0 == 0xC0 => {
                p.get(o + 1)?;
                return Some(o + 2);
            }
            l if l & 0xC0 != 0 => return None,
            l => o += 1 + l as usize,
        }
    }
}

/// Read a name (following compression pointers, at most 16 of them) into dotted form.
fn read_name(p: &[u8], mut o: usize) -> Option<alloc::string::String> {
    let mut name = alloc::string::String::new();
    let mut jumps = 0;
    loop {
        let l = *p.get(o)? as usize;
        if l == 0 {
            return Some(name);
        }
        if l & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            o = (l & 0x3F) << 8 | *p.get(o + 1)? as usize;
            continue;
        }
        if l & 0xC0 != 0 {
            return None;
        }
        let label = p.get(o + 1..o + 1 + l)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(core::str::from_utf8(label).ok()?);
        o += 1 + l;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub id: u16,
    pub rcode: u8,
    /// The addresses for `question`, following CNAMEs inside the message.
    pub addrs: Vec<Ip>,
    pub question: alloc::string::String,
}

pub fn parse_dns_response(p: &[u8]) -> Option<DnsAnswer> {
    if p.len() < 12 || p[2] & 0x80 == 0 {
        return None; // not a response
    }
    let (id, rcode) = (be16(p, 0), p[3] & 0xF);
    let (qd, an) = (be16(p, 4) as usize, be16(p, 6) as usize);
    let mut o = 12;
    let mut question = alloc::string::String::new();
    for i in 0..qd {
        if i == 0 {
            question = read_name(p, o)?;
        }
        o = skip_name(p, o)? + 4;
    }
    let mut want = question.to_ascii_lowercase();
    let mut addrs = Vec::new();
    for _ in 0..an {
        let owner = read_name(p, o)?.to_ascii_lowercase();
        o = skip_name(p, o)?;
        let (ty, _class, rdlen) = (be16(p, o), be16(p, o + 2), be16(p, o + 8) as usize);
        let data = p.get(o + 10..o + 10 + rdlen)?;
        o += 10 + rdlen;
        if owner != want {
            continue;
        }
        match ty {
            DNS_A if rdlen == 4 => addrs.push(data.try_into().unwrap()),
            DNS_CNAME => want = read_name(p, o - rdlen)?.to_ascii_lowercase(),
            _ => {}
        }
    }
    Some(DnsAnswer { id, rcode, addrs, question })
}
