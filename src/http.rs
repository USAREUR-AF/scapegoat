// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! A small HTTP/1.0 server (one thread per connection, the connection closed after each
//! answer, as Python's http.server did) and a plain-HTTP client for the CLI, island publish
//! and the Zenoh REST outputs.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_BODY: usize = 64 * 1024;

pub struct Request {
    pub method: String,
    /// The raw request target, path and query, not percent-decoded.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub client: SocketAddr,
    /// The declared Content-Length was larger than MAX_BODY (the body was not read).
    pub too_large: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "",
    }
}

fn http_date() -> String {
    let ts = crate::clock::wall();
    let (y, mo, d, h, mi, s, _) = crate::clock::civil(ts);
    let days = (ts / 86400.0).floor() as i64;
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(mo - 1) as usize];
    format!("{wd}, {d:02} {mon} {y} {h:02}:{mi:02}:{s:02} GMT")
}

fn read_request(stream: &TcpStream, client: SocketAddr) -> io::Result<Option<Request>> {
    let mut r = BufReader::new(stream);
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(None);
    }
    let (method, target) = (parts[0].to_string(), parts[1].to_string());
    let mut headers = vec![];
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let n: usize = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
    let mut body = vec![];
    let too_large = n > MAX_BODY;
    if n > 0 && !too_large {
        body.resize(n, 0);
        r.read_exact(&mut body)?;
    }
    Ok(Some(Request { method, target, headers, body, client, too_large }))
}

fn write_response(mut stream: &TcpStream, resp: &Response) -> io::Result<()> {
    let head = format!(
        "HTTP/1.0 {} {}\r\nServer: scapegoat\r\nDate: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\r\n",
        resp.status,
        reason(resp.status),
        http_date(),
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

pub type Handler = Arc<dyn Fn(&Request) -> Response + Send + Sync>;

/// A running server. `stop()` closes the listener.
pub struct Server {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    pub fn bind(addr: &str, handler: Handler) -> io::Result<Server> {
        let sa = addr.to_socket_addrs()?.next().ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))?;
        let listener = TcpListener::bind(sa)?;
        let local = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let thread = std::thread::Builder::new().name("scapegoat-http".into()).spawn(move || {
            for conn in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = conn else { continue };
                let h = handler.clone();
                let _ = std::thread::Builder::new().name("scapegoat-http-conn".into()).spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                    let client = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                    if let Ok(Some(req)) = read_request(&stream, client) {
                        let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(&req))) {
                            Ok(r) => r,
                            Err(_) => Response {
                                status: 500,
                                content_type: "application/json".into(),
                                body: b"{\"error\": \"internal error\"}".to_vec(),
                            },
                        };
                        let _ = write_response(&stream, &resp);
                    }
                    let _ = stream.shutdown(Shutdown::Both);
                });
            }
        })?;
        Ok(Server { addr: local, stop, thread: Some(thread) })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop.
        let mut wake = self.addr;
        if wake.ip().is_unspecified() {
            wake.set_ip(if wake.is_ipv4() { "127.0.0.1".parse().unwrap() } else { "::1".parse().unwrap() });
        }
        let _ = TcpStream::connect_timeout(&wake, Duration::from_millis(500));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.stop();
        }
    }
}

/// What a client call got back.
#[derive(Debug)]
pub struct ClientResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A client call failed before an HTTP answer arrived.
#[derive(Debug)]
pub struct ClientError(pub String);

/// `http://host:port/path` -> (host, port, path).
pub fn split_url(url: &str) -> Result<(String, u16, String), ClientError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| ClientError(format!("unknown url type: {}", crate::pyfmt::str_repr(url))))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, p) = h.split_once(']').unwrap_or((h, ""));
        (h.to_string(), p.trim_start_matches(':').to_string())
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (hostport.to_string(), String::new()),
        }
    };
    let port = if port.is_empty() { 80 } else { port.parse().map_err(|_| ClientError(format!("nonnumeric port: '{port}'")))? };
    Ok((host, port, path))
}

/// One HTTP request; the connection is closed after the answer.
pub fn request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<ClientResponse, ClientError> {
    let (host, port, path) = split_url(url)?;
    let addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs().map_err(|e| ClientError(crate::pyfmt::os_error(&e)))?.collect();
    let mut last = ClientError("no address".into());
    let mut stream = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = ClientError(crate::pyfmt::os_error(&e)),
        }
    }
    let mut s = stream.ok_or(last)?;
    let io_err = |e: io::Error| ClientError(crate::pyfmt::os_error(&e));
    s.set_read_timeout(Some(timeout)).map_err(io_err)?;
    s.set_write_timeout(Some(timeout)).map_err(io_err)?;
    let hostname = if port == 80 { host.clone() } else { format!("{host}:{port}") };
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: scapegoat\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).map_err(io_err)?;
    if let Some(b) = body {
        s.write_all(b).map_err(io_err)?;
    }
    let mut raw = vec![];
    s.read_to_end(&mut raw).map_err(io_err)?;
    parse_response(&raw).ok_or_else(|| ClientError("Remote end closed connection without response".into()))
}

fn parse_response(raw: &[u8]) -> Option<ClientResponse> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&raw[..end]).to_string();
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    let mut body = raw[end + 4..].to_vec();
    let chunked = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.eq_ignore_ascii_case("chunked"));
    if chunked {
        body = dechunk(&body);
    } else if let Some(n) =
        headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse::<usize>().ok())
    {
        body.truncate(n);
    }
    Some(ClientResponse { status, headers, body })
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    while let Some(i) = b.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(String::from_utf8_lossy(&b[..i]).split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if size == 0 || b.len() < i + 2 + size {
            break;
        }
        out.extend_from_slice(&b[i + 2..i + 2 + size]);
        b = &b[(i + 4 + size).min(b.len())..];
    }
    out
}

/// Python's `parse_qs`: `a=1&b=x+y` -> [(a, 1), (b, "x y")], blank values dropped.
pub fn parse_qs(q: &str) -> Vec<(String, String)> {
    q.split(['&', ';'])
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            let v = unquote_plus(v);
            if v.is_empty() {
                return None;
            }
            Some((unquote_plus(k), v))
        })
        .collect()
}

pub fn unquote_plus(s: &str) -> String {
    let b = s.replace('+', " ").into_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&b[i + 1..i + 3]), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn quote(s: &str) -> String {
    s.bytes()
        .map(|c| if c.is_ascii_alphanumeric() || b"_.-~/".contains(&c) { (c as char).to_string() } else { format!("%{c:02X}") })
        .collect()
}
