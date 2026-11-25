// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Traffic entries (what the session sent and received) and wire capture.
//!
//! Entry shape, shared by the session log and wire mode:
//!   {seq, time, ts, direction "rx"|"tx"|"fwd"|"wire"|"dgram"|"ctl", peer "ip:port", length,
//!    name, ok, problems, fields, hex}  (+ src, dst for wire entries)

use crate::clock;
use crate::protocol::Decoded;
use serde_json::{json, Map, Value};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const MAX_WIRE_SECONDS: f64 = 60.0;
pub const MAX_WIRE_PACKETS: usize = 2000;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn make_entry(direction: &str, peer: &str, data: &[u8], msg: Option<&Decoded>, ts: Option<f64>) -> Map<String, Value> {
    let ts = ts.unwrap_or_else(clock::wall);
    let (name, ok, problems, fields) = match msg {
        Some(m) => (
            if m.name.is_empty() { "unknown".to_string() } else { m.name.clone() },
            m.ok,
            m.problems.clone(),
            Value::Object(m.fields.clone()),
        ),
        None => ("unknown".to_string(), false, vec![], json!({})),
    };
    let v = json!({
        "time": clock::iso_ms(ts), "ts": ts, "direction": direction, "peer": peer,
        "length": data.len(), "name": name, "ok": ok, "problems": problems,
        "fields": fields, "hex": hex(data),
    });
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

/// One UDP packet seen by tcpdump.
#[derive(Clone, Debug, PartialEq)]
pub struct WirePacket {
    pub time: String,
    pub src: String,
    pub dst: String,
    pub payload: Vec<u8>,
}

/// IP packet (no link header, as `tcpdump -x` prints) -> UDP payload.
pub fn udp_payload(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }
    let off = match packet[0] >> 4 {
        4 => {
            let ihl = ((packet[0] & 0x0F) as usize) * 4;
            if packet.len() < ihl + 8 || packet[9] != 17 {
                return None;
            }
            ihl
        }
        6 => {
            if packet.len() < 48 || packet[6] != 17 {
                return None;
            }
            40
        }
        _ => return None,
    };
    let ulen = u16::from_be_bytes([packet[off + 4], packet[off + 5]]) as usize;
    let mut payload = packet[off + 8..].to_vec();
    if ulen >= 8 {
        payload.truncate(ulen - 8);
    }
    Some(payload)
}

fn is_ts(line: &str) -> Option<(String, &str)> {
    let b = line.as_bytes();
    if b.len() < 10 {
        return None;
    }
    let dd = |i: usize| b[i].is_ascii_digit() && b[i + 1].is_ascii_digit();
    if !(dd(0) && b[2] == b':' && dd(3) && b[5] == b':' && dd(6) && b[8] == b'.') {
        return None;
    }
    let mut i = 9;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 9 || i >= b.len() || !(b[i] as char).is_whitespace() {
        return None;
    }
    Some((line[..i].to_string(), &line[i..]))
}

fn split_port(tok: &str) -> Option<(String, String)> {
    let (h, p) = tok.rsplit_once('.')?;
    if h.is_empty() || p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((h.to_string(), p.to_string()))
}

/// The header line of a UDP packet: (time, src, dst).
fn head(line: &str) -> Option<(String, String, String)> {
    let (time, rest) = is_ts(line)?;
    let toks: Vec<&str> = rest.split_whitespace().collect();
    for i in 0..toks.len() {
        if (toks[i] == "IP" || toks[i] == "IP6") && i + 3 < toks.len() {
            let (Some((sh, sp)), true) = (split_port(toks[i + 1]), toks[i + 2] == ">") else { continue };
            let Some(d) = toks[i + 3].strip_suffix(':') else { continue };
            let Some((dh, dp)) = split_port(d) else { continue };
            return Some((time, format!("{sh}:{sp}"), format!("{dh}:{dp}")));
        }
    }
    None
}

fn hexline(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.len() == line.len() {
        return None;
    }
    let rest = t.strip_prefix("0x")?;
    let colon = rest.find(':')?;
    if colon == 0 || !rest[..colon].chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let body = &rest[colon + 1..];
    if !body.starts_with(char::is_whitespace) {
        return None;
    }
    let body = body.trim_start();
    let mut out = String::new();
    let mut prev_space = false;
    for c in body.chars() {
        if c.is_ascii_hexdigit() {
            out.push(c);
            prev_space = false;
        } else if c.is_whitespace() && !prev_space {
            prev_space = true;
        } else {
            break;
        }
    }
    if out.len() < 2 {
        return None;
    }
    Some(out)
}

/// Parse `tcpdump -nn -x` output into packets.
pub fn parse_tcpdump_x(text: &str) -> Vec<WirePacket> {
    let mut out = vec![];
    let mut cur: Option<(String, String, String)> = None;
    let mut hexbuf = String::new();
    let flush = |cur: &Option<(String, String, String)>, hexbuf: &str, out: &mut Vec<WirePacket>| {
        if let Some((t, s, d)) = cur {
            let pkt = unhex(hexbuf).unwrap_or_default();
            if let Some(p) = udp_payload(&pkt) {
                out.push(WirePacket { time: t.clone(), src: s.clone(), dst: d.clone(), payload: p });
            }
        }
    };
    for line in text.lines() {
        if let Some(h) = head(line) {
            flush(&cur, &hexbuf, &mut out);
            cur = Some(h);
            hexbuf.clear();
            continue;
        }
        if is_ts(line).is_some() {
            // another packet (ICMP, no ports): its hex is not ours
            flush(&cur, &hexbuf, &mut out);
            cur = None;
            hexbuf.clear();
            continue;
        }
        if let (Some(h), true) = (hexline(line), cur.is_some()) {
            hexbuf.push_str(&h);
        }
    }
    flush(&cur, &hexbuf, &mut out);
    out
}

/// [{router, target, line, hint}] for each distinct ICMP unreachable in tcpdump -nn output.
pub fn icmp_unreachable(text: &str) -> Vec<Value> {
    let mut out = vec![];
    let mut seen: Vec<(String, String)> = vec![];
    for line in text.lines() {
        let toks: Vec<&str> = line.split(' ').collect();
        for i in 0..toks.len() {
            if toks[i] != "IP" || i + 5 >= toks.len() {
                continue;
            }
            if toks[i + 2] != ">" || !toks[i + 3].ends_with(':') || toks[i + 4] != "ICMP" || toks[i + 1].is_empty() {
                continue;
            }
            let mut j = i + 5;
            if (toks[j] == "host" || toks[j] == "net") && j + 1 < toks.len() {
                j += 1;
            }
            let target = toks[j];
            let mut k = j + 1;
            if k + 2 < toks.len() && toks[k] == "udp" && toks[k + 1] == "port" && toks[k + 2].chars().all(|c| c.is_ascii_digit()) {
                k += 3;
            }
            if target.is_empty() || k >= toks.len() || !toks[k].starts_with("unreachable") {
                continue;
            }
            let router = toks[i + 1].to_string();
            let key = (router.clone(), target.to_string());
            if !seen.contains(&key) {
                seen.push(key);
                out.push(json!({
                    "router": router, "target": target, "line": line.trim(),
                    "hint": format!("The router {router} cannot find the sensor at {target}: the sensor link not enabled, wrong address, or the sensor not on that segment."),
                }));
            }
            break;
        }
    }
    out
}

fn which(name: &str) -> Option<String> {
    for d in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = std::path::Path::new(d).join(name);
        if p.is_file() {
            return Some(p.to_string_lossy().to_string());
        }
    }
    None
}

/// What one capture round found.
pub struct Capture {
    pub packets: Vec<WirePacket>,
    pub unreachable: Vec<Value>,
    pub error: String,
}

/// Run tcpdump for `seconds` on UDP `port`.
pub fn wire_capture(port: u16, seconds: f64, iface: &str) -> Capture {
    let Some(tcpdump) =
        which("tcpdump").or_else(|| std::path::Path::new("/usr/sbin/tcpdump").is_file().then(|| "/usr/sbin/tcpdump".to_string()))
    else {
        return Capture { packets: vec![], unreachable: vec![], error: "tcpdump is not installed (apt install tcpdump)".into() };
    };
    let seconds = seconds.clamp(1.0, MAX_WIRE_SECONDS);
    let mut cmd = Command::new(&tcpdump);
    cmd.args(["-nn", "-l", "-x", "-c", &MAX_WIRE_PACKETS.to_string()]);
    if !(iface == "any" && cfg!(target_os = "macos")) {
        cmd.args(["-i", iface]);
    }
    cmd.args(["udp", "port", &port.to_string(), "or", "icmp"]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Capture { packets: vec![], unreachable: vec![], error: format!("cannot run tcpdump: {}", crate::pyfmt::os_error(&e)) }
        }
    };
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let to = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = so.read_to_string(&mut s);
        s
    });
    let te = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = se.read_to_string(&mut s);
        s
    });
    let status = wait_with_timeout(&mut child, Duration::from_secs_f64(seconds));
    let out = to.join().unwrap_or_default();
    let err = te.join().unwrap_or_default();
    let packets = parse_tcpdump_x(&out);
    let unreachable = icmp_unreachable(&out);
    let mut error = String::new();
    let code = status_code(status);
    if packets.is_empty() && unreachable.is_empty() && !matches!(code, Some(0) | None | Some(-15)) && !err.trim().is_empty() {
        let lines: Vec<&str> = err.trim().lines().filter(|x| !x.contains("listening on")).collect();
        if let Some(last) = lines.last() {
            error = last.to_string();
            if error.contains("ermission") || error.contains("not permitted") {
                error.push_str(" (wire capture needs root: the systemd service runs as root)");
            }
        }
    }
    Capture { packets, unreachable, error }
}

fn status_code(s: Option<std::process::ExitStatus>) -> Option<i32> {
    let s = s?;
    if let Some(c) = s.code() {
        return Some(c);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = s.signal() {
            return Some(-sig);
        }
    }
    None
}

/// Wait up to `limit`; then SIGTERM, 3 s more, then kill.
pub fn wait_with_timeout(child: &mut std::process::Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let end = Instant::now() + limit;
    loop {
        if let Ok(Some(s)) = child.try_wait() {
            return Some(s);
        }
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(Some(s)) = child.try_wait() {
            return Some(s);
        }
        if Instant::now() >= end {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    child.wait().ok()
}
