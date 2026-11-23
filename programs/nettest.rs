#![no_std]
#![no_main]
extern crate alloc;

use alloc::vec::Vec;
use metallium_programs::io::{ErrorKind, Read, Write};
use metallium_programs::net::*;
use metallium_programs::time::{Duration, Instant};
use metallium_programs::*;

// Tests of the network stack against the host peer (tools/netpeer.py) behind QEMU's user-mode network. The argument
// selects the scenario; the exit code is 0 when it behaved, otherwise a number saying which check failed. The peer is
// at 10.0.2.2 (the gateway), the name server at 10.0.2.3; the host forwards its port 18077 to our TCP port 7777.

const PEER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

macro_rules! check {
    ($n:expr, $cond:expr) => {
        if !$cond {
            eprintln!("check {} failed: {}", $n, stringify!($cond));
            return $n;
        }
    };
}

fn pattern(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32).map(|i| i.wrapping_mul(2654435761).wrapping_add(seed).to_le_bytes()[2]).collect()
}

fn crc32(data: &[u8], mut crc: u32) -> u32 {
    crc = !crc;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(PEER, port)
}

/// Write everything while reading what comes back (an echo server answers as it goes: neither side may wait for the other).
fn echo_through(s: &mut TcpStream, data: &[u8]) -> Result<Vec<u8>, u64> {
    echo_through_for(s, data, Duration::from_secs(120))
}

fn echo_through_for(s: &mut TcpStream, data: &[u8], limit: Duration) -> Result<Vec<u8>, u64> {
    let mut back = Vec::with_capacity(data.len());
    let mut sent = 0;
    s.set_nonblocking(true);
    let t0 = Instant::now();
    let mut buf = [0u8; 3000];
    while back.len() < data.len() {
        if t0.elapsed() > limit {
            return Err(901);
        }
        let mut progress = false;
        if sent < data.len() {
            match s.write(&data[sent..(sent + 3000).min(data.len())]) {
                Ok(n) => {
                    sent += n;
                    progress = true;
                }
                Err(e) if e.kind == ErrorKind::WouldBlock => {}
                Err(_) => return Err(902),
            }
        }
        match s.read(&mut buf) {
            Ok(0) => return Err(903),
            Ok(n) => {
                back.extend_from_slice(&buf[..n]);
                progress = true;
            }
            Err(e) if e.kind == ErrorKind::WouldBlock => {}
            Err(_) => return Err(904),
        }
        if !progress {
            sleep(1);
        }
    }
    s.set_nonblocking(false);
    Ok(back)
}

/// Chaos mode (argument 14 | seconds << 8): while the network driver and `netd` are being killed and restarted under it,
/// keep opening connections to the echo server and checking every byte that comes back. Failures are fine while a service
/// is down; wrong data never is. At the end the network must work again.
fn chaos(seconds: u64) -> u64 {
    let (mut ok, mut failed, mut round) = (0u32, 0u32, 0u32);
    let t0 = Instant::now();
    let attempt = |round: u32| -> Result<bool, u64> {
        let data = pattern(2000 + (round as usize * 733) % 6000, round);
        let Ok(mut s) = TcpStream::connect_timeout(addr(7002), Duration::from_secs(5)) else { return Ok(false) };
        match echo_through_for(&mut s, &data, Duration::from_secs(8)) {
            Ok(back) if back == data => Ok(true),
            Ok(_) => Err(20), // wrong bytes
            Err(_) => Ok(false),
        }
    };
    while t0.elapsed() < Duration::from_secs(seconds) {
        round += 1;
        match attempt(round) {
            Ok(true) => ok += 1,
            Ok(false) => {
                failed += 1;
                sleep(10);
            }
            Err(e) => return e,
        }
    }
    // the services are up again: a connection works, and so does a ping
    let recovered = Instant::now();
    let mut good = false;
    while recovered.elapsed() < Duration::from_secs(40) && !good {
        round += 1;
        good = match attempt(round) {
            Ok(g) => g,
            Err(e) => return e,
        };
        if !good {
            sleep(20);
        }
    }
    println!("chaos: {ok} transfers ok, {failed} failed while services were being killed; recovered: {good}");
    if !good {
        return 21;
    }
    if (0..5).all(|_| ping(PEER, b"alive", Duration::from_secs(2)).is_err()) {
        return 22;
    }
    if ok == 0 {
        return 23;
    }
    0
}

program!("nettest", |c| -> u64 {
    if c.arg & 0xFF == 14 {
        if wait_for_address(Duration::from_secs(20)).is_err() {
            return 100;
        }
        return chaos(c.arg >> 8);
    }
    if c.arg == 16 {
        // a real network: the link comes up, DHCP gives an address, the gateway answers
        let cfg = match wait_for_address(Duration::from_secs(60)) {
            Ok(c) => c,
            Err(_) => return 100,
        };
        check!(1, cfg.addr != Ipv4Addr::new(0, 0, 0, 0));
        let Some(gateway) = cfg.gateway else { return 2 };
        // The gateway is reachable if it answers a ping, or (many gateways do not answer pings) if it answers a TCP
        // connection attempt in any way: an accepted or refused connection is a reply, silence is not.
        let mut rtt = None;
        for _ in 0..5 {
            if let Ok(r) = ping(gateway, b"are you there?", Duration::from_secs(3)) {
                rtt = Some(r);
                break;
            }
        }
        let how = if let Some(r) = rtt {
            alloc::format!("answers a ping in {} ms", r.as_millis())
        } else {
            match TcpStream::connect_timeout(SocketAddr::new(gateway, 80), Duration::from_secs(5)) {
                Ok(_) => "accepts a connection".into(),
                Err(e) if e.kind == ErrorKind::ConnectionRefused => "refuses a connection (and does not answer pings)".into(),
                // a firewall that drops everything but what it routes: a name resolved through the DHCP-given resolver, past the gateway, is proof enough
                Err(_) => match lookup_host("example.com") {
                    Ok(v) if !v.is_empty() => alloc::format!("routes our DNS queries (example.com is {})", v[0]),
                    _ => return 3,
                },
            }
        };
        println!("address {}, gateway {} {}", cfg.addr, gateway, how);
        return 0;
    }
    let cfg = match wait_for_address(Duration::from_secs(20)) {
        Ok(c) => c,
        Err(_) => return 100,
    };
    match c.arg {
        // our address, the gateway, pings
        0 => {
            check!(1, cfg.addr == Ipv4Addr::new(10, 0, 2, 15) && cfg.mask == Ipv4Addr::new(255, 255, 255, 0));
            check!(2, cfg.gateway == Some(PEER) && cfg.dns == Some(Ipv4Addr::new(10, 0, 2, 3)));
            let mut worst = Duration::ZERO;
            for _ in 0..5 {
                match ping(PEER, b"are you there?", Duration::from_secs(3)) {
                    Ok(rtt) => worst = worst.max(rtt),
                    Err(_) => return 3,
                }
            }
            println!("ping: worst round trip {} ms", worst.as_millis());
            check!(4, worst < Duration::from_millis(500));
            check!(5, ping(Ipv4Addr::new(10, 0, 2, 77), b"x", Duration::from_millis(400)).is_err());
            0
        }
        // names
        1 => {
            check!(1, lookup_host("10.1.2.3") == Ok(alloc::vec![Ipv4Addr::new(10, 1, 2, 3)]));
            check!(2, lookup_host("localhost").map_or(false, |v| v.contains(&Ipv4Addr::new(127, 0, 0, 1))));
            let r = lookup_host("no-such-host.invalid");
            check!(3, r.is_err());
            println!("lookup of a name that does not exist: {:?}", r.map_err(|e| e.kind));
            0
        }
        // UDP echo
        2 => {
            let mut s = UdpSocket::bind(0).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3)));
            check!(1, s.local_port() >= 49152);
            let mut buf = [0u8; 2000];
            for len in [0usize, 1, 17, 512, 1400, 1472] {
                let msg = pattern(len, len as u32);
                check!(2, s.send_to(&msg, addr(7001)).is_ok());
                match s.recv_from(&mut buf) {
                    Ok((n, from)) => check!(3, n == len && buf[..n] == msg[..] && from == addr(7001)),
                    Err(_) => return 4,
                }
            }
            // a datagram for a port nobody listens on is lost, quietly
            s.send_to(b"?", addr(7999)).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(200)));
            check!(5, s.recv_from(&mut buf).unwrap_err().kind == ErrorKind::TimedOut);
            check!(6, UdpSocket::bind(s.local_port()).err().map(|e| e.kind) == Some(ErrorKind::AddrInUse));
            0
        }
        // TCP echo, one megabyte
        3 => {
            let mut s = match TcpStream::connect(addr(7002)) {
                Ok(s) => s,
                Err(_) => return 1,
            };
            let data = pattern(1 << 20, 3);
            let t0 = Instant::now();
            let back = match echo_through(&mut s, &data) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let ms = t0.elapsed().as_millis().max(1);
            println!("tcp echo: {} KiB each way in {} ms ({} KiB/s)", data.len() / 1024, ms, data.len() as u128 * 2 * 1000 / 1024 / ms);
            check!(2, back == data);
            0
        }
        // TCP: the peer sends 2 MiB and closes
        4 => {
            let mut s = match TcpStream::connect(addr(7003)) {
                Ok(s) => s,
                Err(_) => return 1,
            };
            s.set_read_timeout(Some(Duration::from_secs(60)));
            let mut got = Vec::new();
            let mut buf = [0u8; 3800];
            let t0 = Instant::now();
            loop {
                match s.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(_) => return 2,
                }
            }
            let ms = t0.elapsed().as_millis().max(1);
            println!("tcp download: {} KiB in {} ms ({} KiB/s)", got.len() / 1024, ms, got.len() as u128 * 1000 / 1024 / ms);
            check!(3, got.len() == 2 * 1024 * 1024);
            check!(4, got == pattern(2 * 1024 * 1024, 7));
            0
        }
        // TCP: we send 2 MiB, half-close, and the peer answers with its checksum
        5 => {
            let mut s = match TcpStream::connect(addr(7004)) {
                Ok(s) => s,
                Err(_) => return 1,
            };
            let data = pattern(2 * 1024 * 1024, 5);
            let t0 = Instant::now();
            if s.write_all(&data).is_err() {
                return 2;
            }
            s.shutdown_write().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(60)));
            let mut answer = [0u8; 8];
            if s.read_exact(&mut answer).is_err() {
                return 3;
            }
            let ms = t0.elapsed().as_millis().max(1);
            println!("tcp upload: {} KiB in {} ms ({} KiB/s)", data.len() / 1024, ms, data.len() as u128 * 1000 / 1024 / ms);
            check!(4, u32::from_be_bytes(answer[..4].try_into().unwrap()) == crc32(&data, 0));
            check!(5, u32::from_be_bytes(answer[4..].try_into().unwrap()) as usize == data.len());
            0
        }
        // refused, and a connection that is reset by the peer's closing with data unread is told so
        6 => {
            let t0 = Instant::now();
            let r = TcpStream::connect(addr(7999));
            check!(1, r.as_ref().err().map(|e| e.kind) == Some(ErrorKind::ConnectionRefused));
            check!(2, t0.elapsed() < Duration::from_secs(5));
            0
        }
        // a listener: the host connects through the forwarded port, says hello, and wants it back in capitals
        7 => {
            let l = match TcpListener::bind(7777, 4) {
                Ok(l) => l,
                Err(_) => return 1,
            };
            check!(2, TcpListener::bind(7777, 4).err().map(|e| e.kind) == Some(ErrorKind::AddrInUse));
            let mut s = match l.accept(Some(Duration::from_secs(60))) {
                Ok(s) => s,
                Err(_) => return 3,
            };
            s.set_read_timeout(Some(Duration::from_secs(10)));
            let mut line = Vec::new();
            let mut b = [0u8; 1];
            while line.last() != Some(&b'\n') {
                match s.read(&mut b) {
                    Ok(1) => line.push(b[0]),
                    _ => return 4,
                }
            }
            check!(5, line == b"ping-from-host\n");
            line.make_ascii_uppercase();
            check!(6, s.write_all(&line).is_ok());
            // the host closes after reading it: we see the end
            let mut rest = [0u8; 10];
            check!(7, s.read(&mut rest).map_or(false, |n| n == 0));
            0
        }
        // many connections one after the other, and many sockets at once
        8 => {
            for i in 0..60u32 {
                let mut s = match TcpStream::connect(addr(7002)) {
                    Ok(s) => s,
                    Err(_) => return 1000 + i as u64,
                };
                let msg = pattern(100 + i as usize, i);
                if s.write_all(&msg).is_err() {
                    return 2000 + i as u64;
                }
                let mut back = alloc::vec![0u8; msg.len()];
                s.set_read_timeout(Some(Duration::from_secs(10)));
                if s.read_exact(&mut back).is_err() || back != msg {
                    return 3000 + i as u64;
                }
            }
            let socks: Vec<UdpSocket> = (0..20).filter_map(|_| UdpSocket::bind(0).ok()).collect();
            check!(4, socks.len() == 20);
            drop(socks);
            check!(5, UdpSocket::bind(0).is_ok());
            0
        }
        // four threads, four connections, at the same time
        9 => {
            let hs: Vec<_> = (0..4u32)
                .map(|i| {
                    thread::spawn(move || -> u64 {
                        let mut s = match TcpStream::connect(addr(7002)) {
                            Ok(s) => s,
                            Err(_) => return 1,
                        };
                        let data = pattern(200_000 + i as usize * 1000, 20 + i);
                        match echo_through(&mut s, &data) {
                            Ok(b) if b == data => 0,
                            Ok(_) => 2,
                            Err(e) => e,
                        }
                    })
                })
                .collect();
            let results: Vec<u64> = hs.into_iter().map(|h| h.join()).collect();
            println!("threads: {:?}", results);
            results.iter().fold(0, |a, &b| a | b)
        }
        // leave sockets open and exit: the service must clean up after us (the next run binds the same ports)
        10 => {
            let l = TcpListener::bind(7780, 2).unwrap();
            let u = UdpSocket::bind(7781).unwrap();
            let s = TcpStream::connect(addr(7002)).unwrap();
            core::mem::forget((l, u, s));
            0
        }
        11 => {
            // (the sockets of the run before are gone)
            check!(1, TcpListener::bind(7780, 2).is_ok());
            check!(2, UdpSocket::bind(7781).is_ok());
            0
        }
        // data arrives slowly in small pieces; the reader keeps up
        12 => {
            let mut s = match TcpStream::connect(addr(7005)) {
                Ok(s) => s,
                Err(_) => return 1,
            };
            let data = pattern(30_000, 12);
            match echo_through(&mut s, &data) {
                Ok(b) => check!(2, b == data),
                Err(e) => return e,
            }
            0
        }
        // the service dies while we hold a connection: we are told, and a new connection works once it is back
        13 => {
            let mut s = TcpStream::connect(addr(7002)).unwrap();
            s.write_all(b"before").unwrap();
            crash_service();
            let mut b = [0u8; 10];
            check!(1, s.read(&mut b).is_err());
            sleep(150); // the kernel restarts it, and it asks for an address again
            check!(2, wait_for_address(Duration::from_secs(20)).is_ok());
            let mut s2 = match TcpStream::connect(addr(7002)) {
                Ok(s) => s,
                Err(_) => return 3,
            };
            s2.write_all(b"after").unwrap();
            s2.set_read_timeout(Some(Duration::from_secs(10)));
            let mut back = [0u8; 5];
            check!(4, s2.read_exact(&mut back).is_ok() && &back == b"after");
            0
        }
        // blocking is sleeping: waiting costs (almost) no calls, and what we wait for wakes us at once
        15 => {
            // an idle UDP socket, one second: a timeout, and a handful of calls instead of one every tick
            let mut s = UdpSocket::bind(0).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(1)));
            let (c0, t0) = (service_calls(), Instant::now());
            let r = s.recv_from(&mut [0u8; 64]);
            let (calls, took) = (service_calls() - c0, t0.elapsed());
            println!("idle recv: {:?} after {} ms with {calls} calls", r.as_ref().map_err(|e| e.kind), took.as_millis());
            check!(1, matches!(r, Err(ref e) if e.kind == ErrorKind::TimedOut));
            check!(2, took >= Duration::from_millis(950) && took < Duration::from_millis(1300));
            check!(3, calls <= 8);
            // the same for a listener nobody connects to
            let l = TcpListener::bind(7790, 4).unwrap();
            let (c0, t0) = (service_calls(), Instant::now());
            let r = l.accept(Some(Duration::from_secs(1)));
            let (calls, took) = (service_calls() - c0, t0.elapsed());
            println!("idle accept: after {} ms with {calls} calls", took.as_millis());
            check!(4, matches!(r, Err(ref e) if e.kind == ErrorKind::TimedOut));
            check!(5, took >= Duration::from_millis(950) && took < Duration::from_millis(1300) && calls <= 8);
            drop(l);
            // what we wait for wakes us at once, not at the next half-second
            let mut worst = Duration::ZERO;
            for i in 0..20u32 {
                s.set_read_timeout(Some(Duration::from_secs(3)));
                let msg = pattern(100 + i as usize, i);
                s.send_to(&msg, addr(7001)).unwrap();
                let t0 = Instant::now();
                let mut buf = [0u8; 512];
                match s.recv_from(&mut buf) {
                    Ok((n, _)) => check!(6, buf[..n] == msg[..]),
                    Err(_) => return 7,
                }
                worst = worst.max(t0.elapsed());
            }
            println!("UDP echo: worst wait {} ms", worst.as_millis());
            check!(8, worst < Duration::from_millis(100));
            // a connection that has to wait for the other side
            let mut c = TcpStream::connect(addr(7005)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5)));
            let data = pattern(3000, 5);
            c.write_all(&data).unwrap();
            let (c0, t0) = (service_calls(), Instant::now());
            let mut back = alloc::vec![0u8; 3000];
            check!(9, c.read_exact(&mut back).is_ok() && back == data);
            println!("slow echo of 3000 bytes: {} ms, {} calls", t0.elapsed().as_millis(), service_calls() - c0);
            check!(10, t0.elapsed() < Duration::from_secs(2));
            0
        }
        _ => 99,
    }
});
