//! A small HTTP/1.0 client for the shell (`download`, `play URL`): it talks to the network service (`netd`) through the shell's own
//! session (endpoint in slot 12, session page in slot 13) and never waits inside the service: every call answers at once, so the
//! loops below poll, running `poll` (draw a frame, look for Ctrl-C) between tries. Plain `http://` only: no TLS here.
use crate::netd::*;
use metallium_driver_rt::*;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

const NET_EP: u64 = 12;
const NET_PAGE: u64 = 13;
const SESSION_VA: usize = 0x8039_0000;

fn page() -> &'static mut [u8; 4096] {
    // SAFETY: SESSION_VA is the 4096-byte session page mapped by `get` before any `page()` call; callers use the reference only transiently (no two live at once); netd writes it only while we are blocked in `call`.
    unsafe { &mut *(va(SESSION_VA) as *mut [u8; 4096]) }
}

fn rpc(op: u64, a: u64, b: u64) -> Result<[u64; 3], u64> {
    match call(NET_EP, [op, a, b]) {
        (0, r) if r[0] == S_OK => Ok(r),
        (0, r) => Err(r[0] | r[1] << 8),
        (e, _) => Err(0x1000 + e as u64),
    }
}

pub struct Url {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(u: &str) -> Result<Url, String> {
    let rest = u.strip_prefix("http://").ok_or_else(|| String::from("only http:// URLs work (no HTTPS here)"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().map_err(|_| String::from("bad port in the URL"))?),
        None => (hostport, 80u16),
    };
    if host.is_empty() {
        return Err(String::from("no host in the URL"));
    }
    Ok(Url { host: String::from(host), port, path: String::from(path) })
}

/// The last path segment (without a query), or `index.html`.
pub fn file_name(u: &Url) -> String {
    let p = u.path.split(['?', '#']).next().unwrap_or("");
    match p.rsplit('/').next() {
        Some(n) if !n.is_empty() => String::from(n),
        _ => String::from("index.html"),
    }
}

fn resolve(host: &str, poll: &mut dyn FnMut() -> bool) -> Result<u32, String> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 {
        let v: Vec<Option<u8>> = parts.iter().map(|p| p.parse().ok()).collect();
        if v.iter().all(Option::is_some) {
            return Ok(u32::from_be_bytes([v[0].unwrap(), v[1].unwrap(), v[2].unwrap(), v[3].unwrap()]));
        }
    }
    let n = host.len().min(200);
    page()[DATA_OFF..DATA_OFF + n].copy_from_slice(&host.as_bytes()[..n]);
    let q = rpc(N_DNS_START, n as u64, 0).map_err(|e| format!("name lookup failed ({e:#x}): is the network up?"))?[1];
    let mut tries = 0;
    let out = loop {
        match rpc(N_DNS_RESULT, q, 0) {
            Ok(r) if r[1] > 0 => {
                let p = page();
                break Ok(u32::from_be_bytes([p[DATA_OFF], p[DATA_OFF + 1], p[DATA_OFF + 2], p[DATA_OFF + 3]]));
            }
            Ok(_) => break Err(format!("{host}: no address")),
            Err(e) if e & 0xff == S_WOULD_BLOCK => {}
            Err(_) => break Err(format!("{host}: cannot resolve")),
        }
        tries += 1;
        if tries > 3000 || poll() {
            break Err(format!("{host}: name lookup timed out"));
        }
        sleep_us(5_000);
    };
    let _ = rpc(N_DNS_RELEASE, q, 0);
    out
}

const DATA_OFF: usize = 256;
const MAXIO: usize = 4096 - DATA_OFF;

/// An open response body.
pub struct Response {
    id: u64,
    pub status: u32,
    pub length: Option<u64>,
    pub location: Option<String>,
    /// body bytes that arrived together with the headers
    pending: Vec<u8>,
    done: bool,
}

impl Response {
    /// Read up to `buf.len()` body bytes; 0 at the end. `poll` returns true to give up.
    pub fn read(&mut self, buf: &mut [u8], poll: &mut dyn FnMut() -> bool) -> Result<usize, String> {
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        if self.done {
            return Ok(0);
        }
        let mut waited = 0u32;
        loop {
            match rpc(N_TCP_READ, self.id, buf.len().min(MAXIO) as u64) {
                Ok(r) => {
                    let n = r[1] as usize;
                    buf[..n].copy_from_slice(&page()[DATA_OFF..DATA_OFF + n]);
                    return Ok(n);
                }
                Err(e) if e & 0xff == S_EOF => {
                    self.done = true;
                    return Ok(0);
                }
                Err(e) if e & 0xff == S_WOULD_BLOCK => {}
                Err(e) => return Err(format!("connection error ({e:#x})")),
            }
            waited += 1;
            if waited > 6000 {
                return Err(String::from("timed out waiting for data"));
            }
            if poll() {
                return Err(String::from("cancelled"));
            }
            sleep_us(2_000);
        }
    }

    pub fn close(self) {
        let _ = rpc(N_TCP_CLOSE, self.id, 0);
    }
}

/// Connect, send a GET and read the headers.
pub fn get(url: &Url, poll: &mut dyn FnMut() -> bool) -> Result<Response, String> {
    if mem_map(NET_PAGE, SESSION_VA, true) != 0 {
        return Err(String::from("no network on this machine"));
    }
    let ip = resolve(&url.host, poll)?;
    let id = rpc(N_TCP_CONNECT, ip as u64, url.port as u64).map_err(|e| format!("cannot connect ({e:#x})"))?[1];
    let mut tries = 0;
    loop {
        match rpc(N_TCP_STATE, id, 0) {
            Ok(r) => match r[1] & 0xff {
                1 | 2 => break,
                4 => {
                    let _ = rpc(N_TCP_CLOSE, id, 0);
                    return Err(format!("cannot connect to {}:{} (refused or timed out)", url.host, url.port));
                }
                _ => {}
            },
            Err(e) => return Err(format!("connection error ({e:#x})")),
        }
        tries += 1;
        if tries > 3000 || poll() {
            let _ = rpc(N_TCP_ABORT, id, 0);
            return Err(String::from("connect timed out"));
        }
        sleep_us(5_000);
    }
    let req = format!("GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: metallium-os\r\nConnection: close\r\n\r\n", url.path, url.host);
    let mut sent = 0;
    while sent < req.len() {
        let n = (req.len() - sent).min(MAXIO);
        page()[DATA_OFF..DATA_OFF + n].copy_from_slice(&req.as_bytes()[sent..sent + n]);
        match rpc(N_TCP_WRITE, id, n as u64) {
            Ok(r) => sent += r[1] as usize,
            Err(e) if e & 0xff == S_WOULD_BLOCK => sleep_us(2_000),
            Err(e) => return Err(format!("send failed ({e:#x})")),
        }
    }
    let mut resp = Response { id, status: 0, length: None, location: None, pending: Vec::new(), done: false };
    // headers: read until the blank line
    let mut head: Vec<u8> = Vec::new();
    let mut chunk = [0u8; MAXIO];
    let end = loop {
        if let Some(i) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if head.len() > 16 * 1024 {
            return Err(String::from("response headers too long"));
        }
        let n = resp.read(&mut chunk, poll)?;
        if n == 0 {
            return Err(String::from("connection closed before the response headers ended"));
        }
        head.extend_from_slice(&chunk[..n]);
    };
    let text = String::from_utf8_lossy(&head[..end]).into_owned();
    let mut lines = text.lines();
    resp.status = lines.next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => resp.length = v.trim().parse().ok(),
                "location" => resp.location = Some(String::from(v.trim())),
                _ => {}
            }
        }
    }
    resp.pending = head[end + 4..].to_vec();
    Ok(resp)
}

/// Follow up to three redirects (to `http://` locations or absolute paths on the same host).
pub fn get_following(url: &Url, poll: &mut dyn FnMut() -> bool) -> Result<Response, String> {
    let mut cur = Url { host: url.host.clone(), port: url.port, path: url.path.clone() };
    for _ in 0..4 {
        let r = get(&cur, poll)?;
        match r.status {
            200 => return Ok(r),
            301 | 302 | 303 | 307 | 308 => {
                let Some(loc) = r.location.clone() else { return Err(format!("HTTP {} without a Location", r.status)) };
                r.close();
                cur = if loc.starts_with('/') { Url { host: cur.host.clone(), port: cur.port, path: loc } } else { parse_url(&loc)? };
            }
            s => {
                r.close();
                return Err(format!("HTTP status {s}"));
            }
        }
    }
    Err(String::from("too many redirects"))
}
