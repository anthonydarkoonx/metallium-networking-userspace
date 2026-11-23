#![no_std]
#![no_main]
extern crate alloc;
use alloc::format;
use alloc::vec::Vec;
use metallium_programs::io::{Read, Write};
use metallium_programs::net::*;
use metallium_programs::time::Duration;
use metallium_programs::*;

// fetch <host> [port] [path]: a plain HTTP/1.0 GET; the response (headers and body) goes to standard output.
program!("fetch", |c| -> u64 {
    let Some(host) = c.argv(1) else {
        eprintln!("usage: fetch <host> [port] [path]");
        return 64;
    };
    let port: u16 = c.argv(2).and_then(|p| p.parse().ok()).unwrap_or(80);
    let path = c.argv(3).unwrap_or("/");
    let addrs = match lookup_host(host) {
        Ok(a) if !a.is_empty() => a,
        _ => {
            eprintln!("fetch: cannot resolve {host}");
            return 1;
        }
    };
    let mut s = match TcpStream::connect_timeout(SocketAddr::new(addrs[0], port), Duration::from_secs(10)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fetch: cannot connect to {}:{port}: {e}", addrs[0]);
            return 2;
        }
    };
    let request = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: metallium-os\r\nConnection: close\r\n\r\n");
    if s.write_all(request.as_bytes()).is_err() {
        return 3;
    }
    s.set_read_timeout(Some(Duration::from_secs(20)));
    let mut total = 0u64;
    let mut buf = [0u8; 2000];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                io::stdout().write_all(&buf[..n]).ok();
            }
            Err(e) => {
                eprintln!("fetch: {e}");
                return 4;
            }
        }
    }
    let _: Vec<u8> = Vec::new();
    if total == 0 { 5 } else { 0 }
});
