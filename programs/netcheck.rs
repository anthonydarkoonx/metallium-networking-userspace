#![no_std]
#![no_main]
use metallium_programs::net::*;
use metallium_programs::time::Duration;
use metallium_programs::*;

// netcheck [name]: the machine's network configuration, a ping to the gateway, and the addresses of `name`, if given.
program!("netcheck", |c| -> u64 {
    let cfg = match wait_for_address(Duration::from_secs(10)) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("no network address: {e}");
            return 1;
        }
    };
    println!("address {}  mask {}  gateway {}  dns {}", cfg.addr, cfg.mask, cfg.gateway.map_or(alloc_str("-"), |g| alloc_fmt(g)), cfg.dns.map_or(alloc_str("-"), |g| alloc_fmt(g)));
    let mut code = 0;
    if let Some(gw) = cfg.gateway {
        match ping(gw, b"metallium os", Duration::from_secs(2)) {
            Ok(rtt) => println!("ping {gw}: {} ms", rtt.as_millis()),
            Err(e) => {
                println!("ping {gw}: {e}");
                code = 2;
            }
        }
    }
    if let Some(name) = c.argv(1) {
        match lookup_host(name) {
            Ok(addrs) => {
                for a in addrs {
                    println!("{name} is {a}");
                }
            }
            Err(e) => {
                println!("{name}: {e}");
                code = 3;
            }
        }
    }
    code
});

extern crate alloc;
fn alloc_str(s: &str) -> alloc::string::String {
    alloc::string::String::from(s)
}
fn alloc_fmt(a: Ipv4Addr) -> alloc::string::String {
    alloc::format!("{a}")
}
