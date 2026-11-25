// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! `scapegoat net`: a read-only view of the node's network aimed at "why is the sensor link
//! not coming up", read-only probes (ping, capture, a route/neighbor check), and guarded
//! controls (add an address, bring a link up, allow the port).
//!
//! Every external command is a list of arguments, never a shell, always with a timeout, and
//! goes through a [`Host`], so tests answer for the machine. Every user-supplied value is
//! validated before it reaches a command line. A control runs only with
//! `allow_net_control = true` in the config AND `confirm = true`; every call, refused or run,
//! goes into an in-memory audit log (last 200).

use crate::ipnet::IfAddr;
use crate::pyfmt;
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::io::Read;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const STAT_KEYS: [&str; 8] = ["rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"];
pub const TOPOLOGIES: [&str; 2] = ["routed", "same-lan"];

/// What the network tools need from the machine.
pub trait Host: Send + Sync {
    /// Run a command. (returncode, stdout, stderr): 127 not found, 124 timed out (with what
    /// it printed so far), 126 could not run.
    fn run(&self, args: &[String], timeout: f64) -> (i32, String, String);
    fn have(&self, cmd: &str) -> bool;
    /// A small /sys or /proc file, trimmed; None if absent.
    fn read_sys(&self, path: &str) -> Option<String>;
    fn list_interfaces(&self) -> Vec<String>;
    /// "Linux" or "Darwin".
    fn system(&self) -> String;
}

/// This machine.
pub struct RealHost;

impl Host for RealHost {
    fn run(&self, args: &[String], timeout: f64) -> (i32, String, String) {
        let mut child =
            match Command::new(&args[0]).args(&args[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return (127, String::new(), format!("{}: command not found", args[0]))
                }
                Err(e) => return (126, String::new(), format!("{}: {}", args[0], pyfmt::os_error(&e))),
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
        let end = Instant::now() + Duration::from_secs_f64(timeout.max(0.0));
        let mut timed_out = false;
        let status = loop {
            if let Ok(Some(s)) = child.try_wait() {
                break Some(s);
            }
            if Instant::now() >= end {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let out = to.join().unwrap_or_default();
        let err = te.join().unwrap_or_default();
        if timed_out {
            return (124, out, format!("{err}\ntimed out after {}s", pyfmt::str(&json!(timeout))).trim().to_string());
        }
        let code = status.and_then(|s| s.code()).unwrap_or(-1);
        (code, out, err)
    }
    fn have(&self, cmd: &str) -> bool {
        crate::node::which(cmd)
    }
    fn read_sys(&self, path: &str) -> Option<String> {
        std::fs::read(path).ok().map(|b| String::from_utf8_lossy(&b).trim().to_string())
    }
    fn list_interfaces(&self) -> Vec<String> {
        let mut names = vec![];
        unsafe {
            let p = libc::if_nameindex();
            if !p.is_null() {
                let mut i = p;
                while (*i).if_index != 0 {
                    names.push(std::ffi::CStr::from_ptr((*i).if_name).to_string_lossy().to_string());
                    i = i.add(1);
                }
                libc::if_freenameindex(p);
            }
        }
        if names.is_empty() {
            if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
                names = rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string())).collect();
            }
        }
        names.sort();
        names
    }
    fn system(&self) -> String {
        if cfg!(target_os = "macos") {
            "Darwin".into()
        } else {
            "Linux".into()
        }
    }
}

/// An argument failed validation; nothing was run.
#[derive(Debug, Clone, PartialEq)]
pub struct Invalid(pub String);

type V<T> = Result<T, Invalid>;

fn inv<T>(s: String) -> V<T> {
    Err(Invalid(s))
}

/// Python `str(v)` of an argument.
fn text(v: &Value) -> String {
    pyfmt::str(v)
}

fn repr(v: &Value) -> String {
    pyfmt::repr(v)
}

/// A time budget for one snapshot.
pub struct Deadline {
    end: Instant,
}

impl Deadline {
    pub fn new(seconds: f64) -> Deadline {
        Deadline { end: Instant::now() + Duration::from_secs_f64(seconds) }
    }
    pub fn left(&self) -> f64 {
        let rem = self.end.saturating_duration_since(Instant::now()).as_secs_f64();
        rem.clamp(0.3, 2.0)
    }
}

pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(true)) => true,
        Some(Value::String(s)) => ["true", "yes", "1"].contains(&s.trim().to_lowercase().as_str()),
        Some(Value::Number(n)) => !n.is_f64() && n.as_i64() == Some(1),
        _ => false,
    }
}

fn get<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}

fn sget(v: &Value, k: &str) -> Option<String> {
    v.get(k).filter(|x| !x.is_null()).map(text)
}

pub fn run_json(host: &dyn Host, args: &[&str], timeout: f64) -> Result<Value, String> {
    let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (rc, out, err) = host.run(&a, timeout);
    if rc != 0 {
        let t = if !err.is_empty() {
            err
        } else if !out.is_empty() {
            out
        } else {
            format!("exit {rc}")
        };
        return Err(t.trim().to_string());
    }
    serde_json::from_str(if out.is_empty() { "[]" } else { &out }).map_err(|e| format!("could not parse output of {}: {e}", args.join(" ")))
}

// ---- validation ---------------------------------------------------------------------------
pub fn iface_name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 15 && n.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

pub fn validate_iface(host: &dyn Host, name: &Value, existing: Option<&[String]>) -> V<String> {
    let Value::String(n) = name else { return inv(format!("interface name {} is not valid", repr(name))) };
    if !iface_name_ok(n) {
        return inv(format!("interface name {} is not valid", repr(name)));
    }
    let names = existing.map(|e| e.to_vec()).unwrap_or_else(|| host.list_interfaces());
    if !names.contains(n) {
        return inv(format!(
            "no interface called {} on this host (have: {})",
            repr(name),
            if names.is_empty() { "none".into() } else { names.join(", ") }
        ));
    }
    Ok(n.clone())
}

pub fn validate_ip(t: &Value) -> V<String> {
    let s = text(t);
    match s.trim().parse::<IpAddr>() {
        Ok(ip) => Ok(ip.to_string()),
        Err(_) => inv(format!("{} is not an IP address", repr(t))),
    }
}

/// Address with prefix for an interface, e.g. 192.0.2.10/24. Prefix required.
pub fn validate_iface_cidr(t: &Value) -> V<String> {
    let Value::String(s) = t else { return inv(format!("{} must be an address with a prefix, e.g. 192.0.2.10/24", repr(t))) };
    if !s.contains('/') {
        return inv(format!("{} must be an address with a prefix, e.g. 192.0.2.10/24", repr(t)));
    }
    IfAddr::parse(s.trim()).map(|a| a.to_string()).ok_or_else(|| Invalid(format!("{} is not a valid address/prefix", repr(t))))
}

/// A network or single address, e.g. 192.0.2.0/24 or 192.0.2.81.
pub fn validate_network(t: &Value) -> V<String> {
    let Value::String(s) = t else { return inv(format!("{} is not a network", repr(t))) };
    IfAddr::parse(s.trim()).map(|a| a.network()).ok_or_else(|| Invalid(format!("{} is not a valid network, e.g. 192.0.2.0/24", repr(t))))
}

fn py_int_of(v: &Value) -> Option<i64> {
    match v {
        Value::Bool(_) => None,
        Value::Number(n) if !n.is_f64() => n.as_i64(),
        Value::Number(n) => crate::config::py_int(&pyfmt::float_repr(n.as_f64()?)),
        other => crate::config::py_int(text(other).trim()),
    }
}

pub fn validate_port(v: &Value) -> V<i64> {
    let Some(p) = py_int_of(v) else { return inv(format!("port {} is not a number", repr(v))) };
    if !(1..=65535).contains(&p) {
        return inv(format!("port {p} is outside 1-65535"));
    }
    Ok(p)
}

pub fn validate_int(v: &Value, name: &str, lo: i64, hi: i64) -> V<i64> {
    let Some(n) = py_int_of(v) else { return inv(format!("{name} {} is not a number", repr(v))) };
    if !(lo..=hi).contains(&n) {
        return inv(format!("{name} {n} is outside {lo}-{hi}"));
    }
    Ok(n)
}

/// '192.0.2.81:47000' -> ('192.0.2.81', Some(47000)). '[v6]:port' supported.
pub fn split_hostport(t: &Value) -> V<(String, Option<i64>)> {
    if t.is_null() {
        return inv("missing address".into());
    }
    let s = text(t).trim().to_string();
    let (host, port) = if let Some(r) = s.strip_prefix('[') {
        let (h, rest) = r.split_once(']').unwrap_or((r, ""));
        (h.to_string(), rest.trim_start_matches(':').to_string())
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (s.clone(), String::new()),
        }
    };
    let ip = validate_ip(&json!(host))?;
    let port = if port.is_empty() { None } else { Some(validate_port(&json!(port))?) };
    Ok((ip, port))
}

// ---- sections -----------------------------------------------------------------------------
fn local_time_z() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&secs, &mut tm);
    }
    let off = tm.tm_gmtoff;
    let sign = if off < 0 { '-' } else { '+' };
    let off = off.abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        off / 3600,
        (off % 3600) / 60
    )
}

fn uname_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().to_string()
}

pub fn host_info(host: &dyn Host) -> Value {
    let mut info =
        json!({"hostname": crate::node::hostname(), "time": local_time_z(), "os": format!("{} {}", host.system(), uname_release())});
    if let Some(up) = host.read_sys("/proc/uptime") {
        if let Some(f) = up.split_whitespace().next().and_then(|x| x.parse::<f64>().ok()) {
            info["uptime_s"] = json!(f as i64);
        }
    }
    info
}

pub fn interfaces(host: &dyn Host, dl: &Deadline) -> Result<Value, String> {
    if !host.have("ip") {
        return mac_interfaces(host, dl);
    }
    let addrs = run_json(host, &["ip", "-j", "addr"], dl.left())?;
    let links = run_json(host, &["ip", "-j", "link"], dl.left())?;
    let link_of = |name: &Value| links.as_array().and_then(|a| a.iter().find(|l| get(l, "ifname") == name).cloned()).unwrap_or(json!({}));
    let mut out = vec![];
    for a in addrs.as_array().cloned().unwrap_or_default() {
        let name = get(&a, "ifname").clone();
        let link = link_of(&name);
        let pick = |k: &str| {
            let v = get(&a, k);
            if crate::config::truthy(Some(v)) {
                v.clone()
            } else {
                get(&link, k).clone()
            }
        };
        let flags = {
            let f = pick("flags");
            if f.is_null() {
                json!([])
            } else {
                f
            }
        };
        let flag_list: Vec<String> = flags.as_array().map(|x| x.iter().map(text).collect()).unwrap_or_default();
        let n = text(&name);
        let carrier_raw = host.read_sys(&format!("/sys/class/net/{n}/carrier"));
        let mut carrier = carrier_raw.map(|c| json!(c == "1")).unwrap_or(Value::Null);
        if carrier.is_null() && flag_list.iter().any(|f| f == "NO-CARRIER") {
            carrier = json!(false);
        }
        let mut stats = Map::new();
        for k in STAT_KEYS {
            if let Some(v) = host.read_sys(&format!("/sys/class/net/{n}/statistics/{k}")) {
                if !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) {
                    stats.insert(k.into(), json!(v.parse::<i64>().unwrap_or(0)));
                }
            }
        }
        let addresses: Vec<Value> = get(&a, "addr_info")
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|ai| crate::config::truthy(ai.get("local")))
            .map(|ai| {
                json!({"family": get(ai, "family"), "address": get(ai, "local"), "prefixlen": get(ai, "prefixlen"),
                       "cidr": format!("{}/{}", text(get(ai, "local")), text(get(ai, "prefixlen"))),
                       "dynamic": crate::config::truthy(ai.get("dynamic"))})
            })
            .collect();
        out.push(json!({
            "name": name, "operstate": pick("operstate"), "admin_up": flag_list.iter().any(|f| f == "UP"),
            "carrier": carrier, "flags": flags, "mac": pick("address"), "mtu": pick("mtu"),
            "addresses": addresses, "stats": stats,
        }));
    }
    Ok(Value::Array(out))
}

fn mac_interfaces(host: &dyn Host, dl: &Deadline) -> Result<Value, String> {
    if !host.have("ifconfig") {
        return Ok(json!({"error": "not available on this OS"}));
    }
    let (rc, out, err) = host.run(&["ifconfig".into(), "-a".into()], dl.left());
    if rc != 0 {
        return Ok(json!({"error": if err.trim().is_empty() { format!("ifconfig exit {rc}") } else { err.trim().to_string() }}));
    }
    Ok(parse_ifconfig(&out))
}

/// Minimal BSD/macOS ifconfig parser: name, flags, mtu, mac, addresses, status.
pub fn parse_ifconfig(t: &str) -> Value {
    let mut result: Vec<Value> = vec![];
    for line in t.lines() {
        if let Some((name, rest)) = line.split_once(": flags=") {
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c)) {
                if let (Some(a), Some(b)) = (rest.find('<'), rest.find('>')) {
                    if rest[..a].chars().all(|c| c.is_ascii_digit()) && !rest[..a].is_empty() {
                        if let Some(m) = rest[b..].find("mtu ") {
                            let mtu: String = rest[b + m + 4..].chars().take_while(|c| c.is_ascii_digit()).collect();
                            if !mtu.is_empty() {
                                let f = &rest[a + 1..b];
                                let flags: Vec<&str> = if f.is_empty() { vec![] } else { f.split(',').collect() };
                                result.push(json!({"name": name, "flags": flags, "admin_up": flags.contains(&"UP"), "mtu": mtu.parse::<i64>().unwrap_or(0),
                                                   "mac": null, "addresses": [], "carrier": null, "operstate": null, "stats": {}}));
                                continue;
                            }
                        }
                    }
                }
            }
        }
        let Some(cur) = result.last_mut() else { continue };
        let s = line.trim();
        let parts: Vec<&str> = s.split_whitespace().collect();
        if let Some(rest) = s.strip_prefix("ether ") {
            cur["mac"] = json!(rest.split_whitespace().next().unwrap_or(""));
        } else if s.starts_with("inet ") {
            let ip = parts.get(1).copied().unwrap_or("");
            let mut prefix: u32 = 32;
            if let Some(i) = parts.iter().position(|p| *p == "netmask") {
                if let Some(mask) = parts.get(i + 1) {
                    if let Some(h) = mask.strip_prefix("0x") {
                        if let Ok(m) = u32::from_str_radix(h, 16) {
                            prefix = m.count_ones();
                        }
                    } else if let Some(a) = IfAddr::parse(&format!("0.0.0.0/{mask}")) {
                        prefix = a.prefix as u32;
                    }
                }
            }
            cur["addresses"]
                .as_array_mut()
                .unwrap()
                .push(json!({"family": "inet", "address": ip, "prefixlen": prefix, "cidr": format!("{ip}/{prefix}")}));
        } else if s.starts_with("inet6 ") {
            let ip = parts.get(1).copied().unwrap_or("").split('%').next().unwrap_or("").to_string();
            let prefix = parts
                .iter()
                .position(|p| *p == "prefixlen")
                .and_then(|i| parts.get(i + 1))
                .and_then(|p| p.parse::<i64>().ok())
                .unwrap_or(128);
            cur["addresses"]
                .as_array_mut()
                .unwrap()
                .push(json!({"family": "inet6", "address": ip, "prefixlen": prefix, "cidr": format!("{ip}/{prefix}")}));
        } else if let Some(st) = s.strip_prefix("status:") {
            let st = st.trim();
            cur["operstate"] = json!(st.to_uppercase());
            cur["carrier"] = json!(st == "active");
        }
    }
    Value::Array(result)
}

pub fn neighbors(host: &dyn Host, dl: &Deadline) -> Result<Value, String> {
    if host.have("ip") {
        let rows = run_json(host, &["ip", "-j", "neigh"], dl.left())?;
        return Ok(Value::Array(
            rows.as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|n| {
                    let st = get(n, "state");
                    json!({"ip": get(n, "dst"), "iface": get(n, "dev"), "mac": get(n, "lladdr"),
                           "state": if crate::config::truthy(Some(st)) { st.clone() } else { json!(["?"]) }})
                })
                .collect(),
        ));
    }
    if host.have("arp") {
        let (rc, out, err) = host.run(&["arp".into(), "-an".into()], dl.left());
        if rc != 0 {
            return Ok(json!({"error": if err.trim().is_empty() { format!("arp exit {rc}") } else { err.trim().to_string() }}));
        }
        let mut res = vec![];
        for line in out.lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            for i in 0..toks.len() {
                let t = toks[i];
                if t.starts_with('(')
                    && t.ends_with(')')
                    && i + 4 < toks.len() + 1
                    && toks.get(i + 1) == Some(&"at")
                    && toks.get(i + 3) == Some(&"on")
                {
                    let ip = &t[1..t.len() - 1];
                    if !ip.is_empty() && ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
                        let mac = toks[i + 2];
                        let inc = mac == "(incomplete)";
                        res.push(json!({"ip": ip, "iface": toks.get(i + 4).copied().unwrap_or(""), "mac": if inc { Value::Null } else { json!(mac) },
                                        "state": if inc { json!(["INCOMPLETE"]) } else { json!(["REACHABLE?"]) }}));
                        break;
                    }
                }
            }
        }
        return Ok(Value::Array(res));
    }
    Ok(json!({"error": "not available on this OS"}))
}

pub fn routes(host: &dyn Host, dl: &Deadline) -> Result<Value, String> {
    if host.have("ip") {
        let rows = run_json(host, &["ip", "-j", "route"], dl.left())?;
        return Ok(Value::Array(
            rows.as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|r| {
                    json!({"dst": get(r, "dst"), "gateway": get(r, "gateway"), "iface": get(r, "dev"), "src": get(r, "prefsrc"),
                           "protocol": get(r, "protocol"), "metric": get(r, "metric")})
                })
                .collect(),
        ));
    }
    if host.have("netstat") {
        let (rc, out, err) = host.run(&["netstat".into(), "-rn".into(), "-f".into(), "inet".into()], dl.left());
        if rc != 0 {
            return Ok(json!({"error": if err.trim().is_empty() { format!("netstat exit {rc}") } else { err.trim().to_string() }}));
        }
        let mut res = vec![];
        for line in out.lines() {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() >= 4 && (p[0] == "default" || p[0].starts_with(|c: char| c.is_ascii_digit())) {
                res.push(json!({"dst": p[0], "gateway": p[1], "iface": p[3]}));
            }
        }
        return Ok(Value::Array(res));
    }
    Ok(json!({"error": "not available on this OS"}))
}

/// Which interface/source/gateway the kernel would use to reach ip.
pub fn route_get(host: &dyn Host, ip: &str, dl: &Deadline) -> Result<Value, String> {
    let ip = validate_ip(&json!(ip)).map_err(|e| e.0)?;
    if host.have("ip") {
        let rows = run_json(host, &["ip", "-j", "route", "get", &ip], dl.left())?;
        let r = rows.as_array().and_then(|a| a.first().cloned()).unwrap_or(json!({}));
        return Ok(json!({"dst": r.get("dst").cloned().unwrap_or(json!(ip)), "iface": get(&r, "dev"), "src": get(&r, "prefsrc"),
                         "gateway": get(&r, "gateway"), "type": get(&r, "type")}));
    }
    if host.have("route") {
        let (rc, out, err) = host.run(&["route".into(), "-n".into(), "get".into(), ip.clone()], dl.left());
        if rc != 0 {
            let t = if !err.is_empty() { err } else { out };
            return Ok(json!({"error": if t.trim().is_empty() { format!("route exit {rc}") } else { t.trim().to_string() }}));
        }
        let mut info = json!({"dst": ip, "iface": null, "src": null, "gateway": null});
        for line in out.lines() {
            let (k, v) = line.trim().split_once(':').unwrap_or((line.trim(), ""));
            match k {
                "interface" => info["iface"] = json!(v.trim()),
                "gateway" => info["gateway"] = json!(v.trim()),
                _ => {}
            }
        }
        return Ok(info);
    }
    Ok(json!({"error": "not available on this OS"}))
}

/// [{local, port, process}] for UDP sockets (ss -uanp).
pub fn udp_listeners(host: &dyn Host, dl: &Deadline) -> Result<Value, String> {
    if host.have("ss") {
        let (rc, out, err) = host.run(&["ss".into(), "-uanp".into()], dl.left());
        if rc != 0 {
            return Err(if err.trim().is_empty() { format!("ss exit {rc}") } else { err.trim().to_string() });
        }
        return Ok(parse_ss(&out));
    }
    if host.have("netstat") {
        let (rc, out, err) = host.run(&["netstat".into(), "-anv".into(), "-p".into(), "udp".into()], dl.left());
        if rc != 0 {
            return Err(if err.trim().is_empty() { format!("netstat exit {rc}") } else { err.trim().to_string() });
        }
        let mut res = vec![];
        for line in out.lines() {
            let p: Vec<&str> = line.split_whitespace().collect();
            if !p.is_empty() && p[0].starts_with("udp") && p.len() >= 4 {
                let (h, port) = p[3].rsplit_once('.').unwrap_or(("", p[3]));
                if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                    res.push(json!({"local": h, "port": port.parse::<i64>().unwrap_or(0), "process": null}));
                }
            }
        }
        return Ok(Value::Array(res));
    }
    Err("neither ss nor netstat is available".into())
}

pub fn parse_ss(t: &str) -> Value {
    let mut res = vec![];
    for line in t.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() < 5 || p[0] == "State" || p[0] == "Netid" {
            continue;
        }
        let offset = if ["udp", "UNCONN", "ESTAB"].contains(&p[0]) && ["UNCONN", "ESTAB"].contains(&p[1]) { 1 } else { 0 };
        let Some(local) = p.get(3 + offset) else { continue };
        let (h, port) = local.rsplit_once(':').unwrap_or(("", local));
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let proc_ = p.get(5 + offset..).map(|x| x.join(" ")).unwrap_or_default();
        let (name, pid) = match proc_.find("((\"") {
            Some(i) => {
                let rest = &proc_[i + 3..];
                match rest.split_once("\",pid=") {
                    Some((n, r)) => {
                        let pid: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
                        if pid.is_empty() {
                            (json!(proc_), Value::Null)
                        } else {
                            (json!(n), json!(pid.parse::<i64>().unwrap_or(0)))
                        }
                    }
                    None => (json!(proc_), Value::Null),
                }
            }
            None => (if proc_.is_empty() { Value::Null } else { json!(proc_) }, Value::Null),
        };
        res.push(json!({"local": h.trim_matches(|c| c == '[' || c == ']'), "port": port.parse::<i64>().unwrap_or(0), "state": p[offset], "process": name, "pid": pid}));
    }
    Value::Array(res)
}

/// Does `line` hold `word` with no letter, digit or `_` either side (regex `\bword\b`)?
pub fn has_word(line: &str, word: &str) -> bool {
    let w = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let mut start = 0;
    while let Some(i) = line[start..].find(word) {
        let a = start + i;
        let b = a + word.len();
        if !w(line[..a].chars().last()) && !w(line[b..].chars().next()) {
            return true;
        }
        start = a + word.len().max(1);
        if start > line.len() {
            break;
        }
    }
    false
}

/// Firewall summary and lines mentioning any of `ports`.
pub fn firewall(host: &dyn Host, ports: &[i64], dl: &Deadline) -> Value {
    let ports: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    if host.have("ufw") {
        let (rc, out, err) = host.run(&["ufw".into(), "status".into(), "verbose".into()], dl.left());
        if rc != 0 {
            let t = if !err.is_empty() { err } else { out };
            return json!({"tool": "ufw", "error": if t.trim().is_empty() { format!("ufw exit {rc}") } else { t.trim().to_string() }});
        }
        let active = out.lines().any(|l| l.strip_prefix("Status:").is_some_and(|r| r.trim_start().starts_with("active")));
        let mentions: Vec<String> = out.lines().filter(|l| ports.iter().any(|p| has_word(l, p))).map(|l| l.trim().to_string()).collect();
        let default_in = out.lines().find_map(|l| {
            let r = l.strip_prefix("Default:")?.trim_start();
            let word: String = r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            let after = r[word.len()..].trim_start();
            (!word.is_empty() && after.starts_with("(incoming)")).then_some(word)
        });
        let summary: Vec<&str> = out.trim().lines().take(30).collect();
        return json!({"tool": "ufw", "active": active, "default_incoming": default_in, "port_rules": mentions, "summary": summary});
    }
    if host.have("nft") {
        let (rc, out, err) = host.run(&["nft".into(), "list".into(), "ruleset".into()], dl.left());
        if rc != 0 {
            let t = if !err.is_empty() { err } else { out };
            return json!({"tool": "nft", "error": if t.trim().is_empty() { format!("nft exit {rc}") } else { t.trim().to_string() }});
        }
        let mentions: Vec<String> =
            out.lines().filter(|l| ports.iter().any(|p| has_word(l, p))).map(|l| l.trim().to_string()).take(40).collect();
        let policies: Vec<String> = out
            .lines()
            .filter(|l| l.contains("policy drop") || l.contains("policy reject"))
            .map(|l| l.trim().to_string())
            .take(10)
            .collect();
        return json!({"tool": "nft", "active": !out.trim().is_empty(), "port_rules": mentions, "drop_policies": policies});
    }
    if host.have("pfctl") {
        return json!({"tool": "pf", "note": "macOS packet filter; not inspected (needs root)"});
    }
    json!({"tool": null, "note": "no ufw or nft found; no host firewall detected"})
}

// ---- session analysis ---------------------------------------------------------------------
fn iface_index(ifaces: &Value) -> Vec<(String, Value)> {
    ifaces.as_array().map(|a| a.iter().map(|i| (text(get(i, "name")), i.clone())).collect()).unwrap_or_default()
}

fn idx_get<'a>(idx: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    idx.iter().find(|(n, _)| n == name).map(|(_, v)| v)
}

fn addrs_of(i: Option<&Value>) -> Vec<Value> {
    i.and_then(|i| i.get("addresses")).and_then(Value::as_array).cloned().unwrap_or_default()
}

/// Interface addresses whose subnet contains peer_ip: [{iface, cidr}].
pub fn same_subnet_addresses(ifaces: &Value, peer_ip: &str) -> Vec<Value> {
    let Ok(peer) = peer_ip.parse::<IpAddr>() else { return vec![] };
    let mut hits = vec![];
    for i in ifaces.as_array().cloned().unwrap_or_default() {
        for a in addrs_of(Some(&i)) {
            let Some(net) = a.get("cidr").and_then(Value::as_str).and_then(IfAddr::parse) else { continue };
            let max = if net.is_v4() { 32 } else { 128 };
            if net.is_v4() == peer.is_ipv4() && net.contains(&peer) && net.prefix < max {
                hits.push(json!({"iface": get(&i, "name"), "cidr": a["cidr"]}));
            }
        }
    }
    hits
}

/// Peers of a session: `peer` first, then `peer_candidates`, deduplicated.
pub fn session_peers(scfg: &Value) -> (Vec<(String, Option<i64>)>, Vec<String>) {
    let mut texts: Vec<Value> = vec![];
    if crate::config::truthy(scfg.get("peer")) {
        texts.push(scfg["peer"].clone());
    }
    match scfg.get("peer_candidates") {
        Some(Value::String(s)) if !s.is_empty() => texts.push(json!(s)),
        Some(Value::Array(a)) => texts.extend(a.iter().cloned()),
        _ => {}
    }
    let (mut peers, mut problems) = (vec![], vec![]);
    for t in texts {
        match split_hostport(&t) {
            Ok(p) => {
                if !peers.contains(&p) {
                    peers.push(p);
                }
            }
            Err(e) => problems.push(format!("{}: {}", repr(&t), e.0)),
        }
    }
    (peers, problems)
}

fn is_virtual(name: &str) -> bool {
    ["lo", "wlan", "wl", "wt", "podman", "veth", "docker", "br-", "virbr", "tailscale", "wg", "tun", "tap", "netbird"]
        .iter()
        .any(|p| name.starts_with(p))
}

fn is_wired(name: &str) -> bool {
    ["eth", "en", "eno", "enp", "ens", "end", "usb"].iter().any(|p| name.starts_with(p))
}

/// Interface to name in an addr_add hint: carrier up and not wireless/virtual. Names in
/// `prefer` win if eligible. The literal "<iface>" when none qualifies.
pub fn sensor_iface_choice(ifaces: &Value, prefer: &[String]) -> String {
    let ok: Vec<String> = ifaces
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter(|i| i.get("carrier") == Some(&json!(true)) && !is_virtual(&sget(i, "name").unwrap_or_default()))
        .map(|i| text(get(i, "name")))
        .collect();
    for n in prefer {
        if ok.contains(n) {
            return n.clone();
        }
    }
    ok.first().cloned().unwrap_or("<iface>".into())
}

/// The configured expected_local_address as an address with prefix, or None.
pub fn expected_address(config: &Value) -> Option<IfAddr> {
    let want = config.get("expected_local_address").filter(|v| crate::config::truthy(Some(v)))?;
    validate_iface_cidr(&json!(text(want))).ok().and_then(|c| IfAddr::parse(&c))
}

fn sessions_of(config: &Value) -> Vec<(String, Value)> {
    match config.get("sessions") {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let sid =
                    sget(s, "id").filter(|x| !x.is_empty()).or_else(|| sget(s, "name").filter(|x| !x.is_empty())).unwrap_or(i.to_string());
                (sid, s.clone())
            })
            .collect(),
        _ => vec![],
    }
}

/// How this node reaches the sensor: routed (through a router) or same-lan.
pub fn topology(host: &dyn Host, config: &Value, ifaces: &Value, dl: &Deadline) -> Value {
    let want = config.get("topology").cloned().unwrap_or(Value::Null);
    if let Value::String(w) = &want {
        if TOPOLOGIES.contains(&w.as_str()) {
            return json!({"mode": w, "source": "config"});
        }
    }
    let note = if want.is_null() || want == json!("") {
        None
    } else {
        Some(format!("topology {} in the config is not one of {}; inferred", repr(&want), TOPOLOGIES.join(", ")))
    };
    let mut out = if expected_address(config).is_some() {
        json!({"mode": "same-lan", "source": "expected_local_address is set"})
    } else {
        let mut o = json!({"mode": "same-lan", "source": "inferred (no peer to check)"});
        for (_, scfg) in sessions_of(config) {
            let (peers, _) = session_peers(&scfg);
            let Some((ip, _)) = peers.first() else { continue };
            let r = route_get(host, ip, dl).unwrap_or(json!({}));
            let gw = r.get("gateway").filter(|g| crate::config::truthy(Some(g))).map(text);
            let routed = gw.is_some() && same_subnet_addresses(ifaces, ip).is_empty();
            o = json!({"mode": if routed { "routed" } else { "same-lan" },
                       "source": format!("inferred from the route to {ip}") + &gw.map(|g| format!(" (via gateway {g})")).unwrap_or_default()});
            break;
        }
        o
    };
    if let Some(n) = note {
        out["note"] = json!(n);
    }
    out
}

/// IPs that are the source of a default route (prefsrc, else the interface's first IPv4).
pub fn default_route_sources(routes_: &Value, ifaces: &Value) -> Vec<String> {
    let idx = iface_index(ifaces);
    let mut out = vec![];
    for r in routes_.as_array().cloned().unwrap_or_default() {
        if r.get("dst") != Some(&json!("default")) {
            continue;
        }
        if crate::config::truthy(r.get("src")) {
            out.push(text(&r["src"]));
        } else if let Some(first) = addrs_of(idx_get(&idx, &text(get(&r, "iface"))))
            .iter()
            .find(|a| a.get("family") == Some(&json!("inet")))
            .map(|a| text(get(a, "address")))
        {
            out.push(first);
        }
    }
    out
}

fn no_carrier_hint(iface: &str) -> String {
    format!("{iface} has no carrier: check the cable to the sensor network switch")
}

fn neighbor_entry(neigh: &Value, target: &str) -> Option<Value> {
    neigh.as_array().and_then(|a| a.iter().find(|n| sget(n, "ip").as_deref() == Some(target)).cloned())
}

fn states_of(entry: &Option<Value>) -> Vec<String> {
    match entry {
        Some(e) => e.get("state").and_then(Value::as_array).map(|a| a.iter().map(|s| text(s).to_uppercase()).collect()).unwrap_or_default(),
        None => vec!["NONE".into()],
    }
}

/// Routed topology: the sensor is on another subnet, reached through a router.
#[allow(clippy::too_many_arguments)]
fn check_peer_routed(
    host: &dyn Host,
    peer_ip: &str,
    peer_port: Option<i64>,
    ifaces: &Value,
    neigh: &Value,
    dl: &Deadline,
    local_ip: Option<&str>,
    default_srcs: &[String],
) -> Value {
    let (mut hints, mut notes): (Vec<String>, Vec<String>) = (vec![], vec![]);
    let matches = same_subnet_addresses(ifaces, peer_ip);
    let r = match route_get(host, peer_ip, dl) {
        Ok(r) => r,
        Err(e) => {
            hints.push(format!("The kernel has no route to {peer_ip} ({e}): add a route to the sensor's subnet through the router, or check the default route."));
            json!({"error": e})
        }
    };
    let idx = iface_index(ifaces);
    let out_iface = r.get("iface").filter(|v| crate::config::truthy(Some(v))).map(text);
    let gw = r.get("gateway").filter(|v| crate::config::truthy(Some(v))).map(text);
    for m in &matches {
        let (mi, mc) = (text(get(m, "iface")), text(get(m, "cidr")));
        let addr = addrs_of(idx_get(&idx, &mi)).into_iter().find(|x| x.get("cidr") == Some(&json!(mc))).unwrap_or(json!({}));
        let own_ip = mc.split('/').next().unwrap_or("").to_string();
        if let Some(g) = &gw {
            // The route already goes via the router (e.g. a host route wins): the overlap does
            // not break routing. Informational only.
            notes.push(format!(
                "{mc} on {mi} overlaps the sensor's subnet, but traffic to {peer_ip} still goes via gateway {g} on {}; no change needed.",
                out_iface.clone().unwrap_or("None".into())
            ));
            continue;
        }
        let peer: IpAddr = peer_ip.parse().unwrap();
        let others: Vec<Value> = addrs_of(idx_get(&idx, &mi))
            .into_iter()
            .filter(|x| {
                x.get("family") == Some(&json!("inet"))
                    && x.get("cidr") != Some(&json!(mc))
                    && !IfAddr::parse(&text(get(x, "cidr"))).is_some_and(|n| n.contains(&peer))
            })
            .collect();
        let protected = crate::config::truthy(addr.get("dynamic")) || default_srcs.contains(&own_ip);
        if !others.is_empty() && !protected {
            hints.push(format!("This node holds {mc} in the sensor's subnet, so it looks for the sensor on its own wire instead of through the router — remove it: scapegoat net addr_del --iface {mi} --cidr {mc} --confirm"));
        } else {
            hints.push(format!("This node's own network {mc} on {mi} includes the sensor address {peer_ip}, so traffic to it is not sent to a router. Check the sensor address, or whether this site is same-lan (topology)."));
        }
    }
    if let Some(oi) = &out_iface {
        let i = idx_get(&idx, oi);
        if i.is_some_and(|i| !crate::config::truthy(i.get("admin_up"))) {
            hints.push(format!("{oi} is administratively down — bring it up with: scapegoat net link_up --iface {oi} --confirm"));
        } else if i.is_some_and(|i| i.get("carrier") == Some(&json!(false))) {
            hints.push(no_carrier_hint(oi));
        }
        let local_here = local_ip.is_some_and(|l| !l.is_empty() && addrs_of(i).iter().any(|a| sget(a, "address").as_deref() == Some(l)));
        if !is_wired(oi) && !local_here {
            let kind = if oi.starts_with("wt") || oi.starts_with("netbird") {
                "NetBird mesh"
            } else if oi.starts_with("wl") || oi.starts_with("wlan") {
                "Wi-Fi"
            } else {
                "a non-wired interface"
            };
            hints.push(format!("Traffic to {peer_ip} would leave on {oi} ({kind}), not on the wired network toward the sensor's router: check the routes (ip route get {peer_ip})."));
        }
        if gw.is_none() && matches.is_empty() {
            hints.push(format!("{peer_ip} is routed directly out of {oi} with no gateway, but the topology is routed: the sensor's router should be the next hop."));
        }
    }
    let target = gw.clone().unwrap_or(peer_ip.to_string());
    let entry = neighbor_entry(neigh, &target);
    let states = states_of(&entry);
    let mut out = json!({"ip": peer_ip, "port": peer_port, "hints": [], "notes": [], "same_subnet": matches, "route": r,
                         "neighbor": entry.clone().unwrap_or(json!({"ip": target, "state": ["NONE"], "mac": null}))});
    if entry.is_none() {
        out["neighbor_note"] = json!(format!("no ARP/neighbor entry for {target} yet (normal before any traffic)"));
    } else if states.iter().any(|s| s == "FAILED" || s == "INCOMPLETE") {
        hints.push(if gw.is_some() {
            format!("The router {target} does not answer ARP ({}): check the cable and the gateway address.", states.join("/"))
        } else {
            format!("{target} does not answer ARP ({}).", states.join("/"))
        });
    }
    out["hints"] = json!(hints);
    out["notes"] = json!(notes);
    out
}

/// Per-peer checks: same subnet, route, interface state, neighbor (ARP).
#[allow(clippy::too_many_arguments)]
fn check_peer(
    host: &dyn Host,
    peer_ip: &str,
    peer_port: Option<i64>,
    ifaces: &Value,
    neigh: &Value,
    dl: &Deadline,
    expected: Option<IfAddr>,
    mode: &str,
    local_ip: Option<&str>,
    default_srcs: &[String],
) -> Value {
    if mode == "routed" {
        return check_peer_routed(host, peer_ip, peer_port, ifaces, neigh, dl, local_ip, default_srcs);
    }
    let mut hints: Vec<String> = vec![];
    let matches = same_subnet_addresses(ifaces, peer_ip);
    if matches.is_empty() {
        if !peer_ip.contains(':') {
            hints.push(subnet_hint(&[peer_ip.to_string()], ifaces, expected));
        } else {
            hints.push(format!("No address on any interface is in the same subnet as peer {peer_ip}."));
        }
    }
    let r = match route_get(host, peer_ip, dl) {
        Ok(r) => r,
        Err(e) => {
            hints.push(format!("The kernel has no route to {peer_ip} ({e})."));
            json!({"error": e})
        }
    };
    let idx = iface_index(ifaces);
    let out_iface = r.get("iface").filter(|v| crate::config::truthy(Some(v))).map(text);
    let gw = r.get("gateway").filter(|v| crate::config::truthy(Some(v))).map(text);
    if let Some(oi) = &out_iface {
        if let Some(i) = idx_get(&idx, oi) {
            if !crate::config::truthy(i.get("admin_up")) {
                hints.push(format!("{oi} is administratively down — bring it up with: scapegoat net link_up --iface {oi} --confirm"));
            } else if i.get("carrier") == Some(&json!(false)) && gw.is_none() {
                hints.push(no_carrier_hint(oi));
            }
        }
        if let (Some(g), false) = (&gw, matches.is_empty()) {
            hints.push(format!(
                "Traffic to {peer_ip} goes via gateway {g} on {oi}, although {} on {} is in its subnet; check for a conflicting route.",
                text(get(&matches[0], "cidr")),
                text(get(&matches[0], "iface"))
            ));
        } else if let Some(g) = &gw {
            hints.push(format!(
                "{peer_ip} is reached through gateway {g} on {oi}, not directly; the sensor normally needs to be on the same subnet."
            ));
        }
        if !matches.is_empty() && !matches.iter().any(|m| text(get(m, "iface")) == *oi) {
            hints.push(format!(
                "Traffic to {peer_ip} leaves on {oi}, not on {} which holds the matching subnet.",
                text(get(&matches[0], "iface"))
            ));
        }
    }
    for m in &matches {
        let mi = text(get(m, "iface"));
        if idx_get(&idx, &mi).is_some_and(|i| i.get("carrier") == Some(&json!(false))) && Some(&mi) != out_iface.as_ref() {
            hints.push(no_carrier_hint(&mi));
        }
    }
    let target = gw.unwrap_or(peer_ip.to_string());
    let entry = neighbor_entry(neigh, &target);
    let states = states_of(&entry);
    let mut out = json!({"ip": peer_ip, "port": peer_port, "hints": [], "same_subnet": matches, "route": r,
                         "neighbor": entry.clone().unwrap_or(json!({"ip": target, "state": ["NONE"], "mac": null}))});
    if entry.is_none() {
        out["neighbor_note"] = json!(format!("no ARP/neighbor entry for {target} yet (normal before any traffic)"));
    } else if states.iter().any(|s| s == "FAILED" || s == "INCOMPLETE") {
        hints.push(format!(
            "{target} does not answer ARP ({}): the sensor is not on this wire, is off, or its address is not {target}.",
            states.join("/")
        ));
    }
    out["hints"] = json!(hints);
    out
}

fn net24(ip: &str) -> IfAddr {
    let a = IfAddr::parse(&format!("{ip}/24")).unwrap();
    IfAddr::parse(&a.network()).unwrap()
}

fn subnet_hint(peer_ips: &[String], ifaces: &Value, expected: Option<IfAddr>) -> String {
    let n = net24(&peer_ips[0]);
    let who = if peer_ips.len() == 1 { format!("peer {}", peer_ips[0]) } else { format!("peers {}", peer_ips.join(", ")) };
    let iface = sensor_iface_choice(ifaces, &[]);
    if let Some(e) = expected {
        if peer_ips[0].parse::<IpAddr>().is_ok_and(|p| e.contains(&p)) {
            return format!("No address on any interface is in {}, the subnet of {who} — add the expected address with: scapegoat net addr_add --iface {iface} --cidr {e} --confirm", e.network());
        }
    }
    format!(
        "No address on any interface is in {}, the subnet of {who} — add one with: scapegoat net addr_add --iface {iface} --cidr {}/24 --confirm  (use the subnet and free address the sensor operator gives you; the sensor only talks to its own subnet)",
        n.network(),
        suggest_host(&n, peer_ips)
    )
}

/// A plausible host address in the peers' /24 for the hint text (not checked as free).
fn suggest_host(n: &IfAddr, peer_ips: &[String]) -> String {
    let IpAddr::V4(base) = n.ip else { return n.ip.to_string() };
    let b = u32::from(base) & 0xffff_ff00;
    let host = |k: u32| std::net::Ipv4Addr::from(b + k).to_string();
    for c in [host(10), host(253), host(2)] {
        if !peer_ips.contains(&c) {
            return c;
        }
    }
    host(1)
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for x in items {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// Session checks. `peers` holds one per-peer result; the top-level peer_ip/peer_port/
/// same_subnet/route/neighbor repeat the first peer's.
#[allow(clippy::too_many_arguments)]
fn analyze_session(
    host: &dyn Host,
    sid: &str,
    scfg: &Value,
    ifaces: &Value,
    neigh: &Value,
    listeners: &Value,
    fw: &Value,
    dl: &Deadline,
    expected: Option<IfAddr>,
    mode: &str,
    default_srcs: &[String],
) -> Value {
    let mut hints: Vec<String> = vec![];
    let (peers, problems) = session_peers(scfg);
    for p in &problems {
        hints.push(format!("Session {sid}: a peer address in the config is not usable ({p})."));
    }
    if peers.is_empty() {
        if problems.is_empty() {
            hints.push(format!("Session {sid}: no peer or peer_candidates set in the config."));
        }
        return json!({"id": sid, "hints": hints, "error": "no usable peer address in config (peer / peer_candidates)"});
    }
    let local = scfg.get("local").cloned().unwrap_or(json!("0.0.0.0:47000"));
    let (local_ip, local_port) = match split_hostport(&local) {
        Ok((i, p)) => (Some(i), p),
        Err(_) => (None, None),
    };
    let li = local_ip.clone().filter(|l| l != "0.0.0.0" && l != "::");
    let peer_res: Vec<Value> = peers
        .iter()
        .map(|(ip, port)| check_peer(host, ip, *port, ifaces, neigh, dl, expected, mode, li.as_deref(), default_srcs))
        .collect();
    let notes = dedupe(
        peer_res
            .iter()
            .flat_map(|p| p.get("notes").and_then(Value::as_array).cloned().unwrap_or_default().iter().map(text).collect::<Vec<_>>())
            .collect(),
    );
    let first = peer_res[0].clone();
    let mut out = json!({"id": sid, "hints": [], "local_ip": local_ip, "local_port": local_port, "protocol": get(scfg, "protocol"),
                         "topology": mode, "peers": peer_res, "notes": notes,
                         "peer_ip": first["ip"], "peer_port": first["port"], "same_subnet": first["same_subnet"],
                         "route": first["route"], "neighbor": first["neighbor"]});
    if let Some(nn) = first.get("neighbor_note") {
        out["neighbor_note"] = nn.clone();
    }
    // one "no address in subnet" hint per /24, naming every candidate in it
    let mut by_net: Vec<(String, Vec<String>)> = vec![];
    if mode != "routed" {
        for p in out["peers"].as_array().unwrap() {
            let ip = text(&p["ip"]);
            if p["same_subnet"].as_array().is_none_or(|a| a.is_empty()) && !ip.contains(':') {
                let key = net24(&ip).network();
                match by_net.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, v)) => v.push(ip),
                    None => by_net.push((key, vec![ip])),
                }
            }
        }
    }
    let mut merged: Vec<(String, String)> = vec![];
    for (_, ips) in &by_net {
        for ip in ips {
            merged.push((subnet_hint(std::slice::from_ref(ip), ifaces, expected), subnet_hint(ips, ifaces, expected)));
        }
    }
    for p in out["peers"].as_array().unwrap().clone() {
        for h in p["hints"].as_array().cloned().unwrap_or_default() {
            let h = text(&h);
            hints.push(merged.iter().rev().find(|(k, _)| *k == h).map(|(_, v)| v.clone()).unwrap_or(h));
        }
    }
    if let Some(l) = &li {
        let have_local = ifaces
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .any(|i| addrs_of(Some(i)).iter().any(|a| sget(a, "address").as_deref() == Some(l)));
        if !have_local {
            hints
                .push(format!("The config binds to {l}, but no interface has that address; the session socket cannot open until it does."));
        }
    }
    let port = local_port.or(first["port"].as_i64());
    if let (Value::Array(ls), Some(port)) = (listeners, port) {
        let mine: Vec<Value> = ls.iter().filter(|l| l.get("port").and_then(Value::as_i64) == Some(port)).cloned().collect();
        out["listeners"] = json!(mine);
        if mine.is_empty() {
            hints.push(format!(
                "Nothing is listening on UDP {port}: the scapegoat session is not running or not enabled (scapegoat status)."
            ));
        } else if !mine.iter().any(|l| {
            let p = l.get("process").filter(|v| !v.is_null()).map(text);
            p.as_deref().unwrap_or("").starts_with("python") || p.is_none() || p.as_deref() == Some("scapegoat")
        }) {
            let mut names: Vec<String> = mine.iter().map(|l| l.get("process").map(text).unwrap_or("None".into())).collect();
            names.sort();
            names.dedup();
            hints.push(format!("UDP {port} is held by another program ({}); scapegoat cannot bind it.", names.join(", ")));
        }
    } else if listeners.is_object() {
        out["listeners"] = listeners.clone();
    }
    if let (true, Some(port)) = (fw.is_object() && crate::config::truthy(fw.get("active")), port) {
        let rules: Vec<String> = fw
            .get("port_rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(text)
            .filter(|l| has_word(l, &port.to_string()))
            .collect();
        out["firewall_rules"] = json!(rules);
        let default_in = fw.get("default_incoming").filter(|v| !v.is_null()).map(text).unwrap_or_default().to_lowercase();
        if fw.get("tool") == Some(&json!("ufw")) && rules.is_empty() && (default_in == "deny" || default_in == "reject") {
            let nets = dedupe(
                out["peers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| {
                        let ip = text(&p["ip"]);
                        if ip.contains(':') {
                            ip
                        } else {
                            net24(&ip).network()
                        }
                    })
                    .collect(),
            );
            let ifc = first["same_subnet"]
                .as_array()
                .and_then(|a| a.first())
                .map(|m| text(get(m, "iface")))
                .or_else(|| first["route"].get("iface").filter(|v| crate::config::truthy(Some(v))).map(text))
                .unwrap_or_else(|| sensor_iface_choice(ifaces, &[]));
            for n in nets {
                hints.push(format!("ufw is active, denies incoming by default, and has no rule for UDP {port}; replies from the sensor will be dropped — allow with: scapegoat net fw_allow --iface {ifc} --from_cidr {n} --port {port} --confirm"));
            }
        }
    }
    out["hints"] = json!(dedupe(hints));
    out
}

/// Is the top-level expected_local_address present on an interface? Read-only.
pub fn expected_local(config: &Value, ifaces: &Value, session_results: &Value) -> Value {
    let Some(want) = config.get("expected_local_address").filter(|v| crate::config::truthy(Some(v))) else { return Value::Null };
    let want_if = match validate_iface_cidr(&json!(text(want))) {
        Ok(c) => IfAddr::parse(&c).unwrap(),
        Err(e) => {
            return json!({"cidr": want, "present": false, "error": e.0, "hints": [format!("expected_local_address in the config is not usable ({}).", e.0)]})
        }
    };
    let cidr = want_if.to_string();
    let (mut on, mut other): (Vec<Value>, Vec<Value>) = (vec![], vec![]);
    for i in ifaces.as_array().cloned().unwrap_or_default() {
        for a in addrs_of(Some(&i)) {
            if sget(&a, "address").as_deref() != Some(&want_if.ip.to_string()) {
                continue;
            }
            if a.get("prefixlen").and_then(Value::as_i64) == Some(want_if.prefix as i64) {
                on.push(get(&i, "name").clone());
            } else {
                other.push(json!({"iface": get(&i, "name"), "cidr": get(&a, "cidr")}));
            }
        }
    }
    let mut res = json!({"cidr": cidr, "present": !on.is_empty(), "on": on, "other_prefix": other, "hints": []});
    if !on.is_empty() {
        return res;
    }
    let hint = if let Some(o) = other.first() {
        let (oi, oc) = (text(get(o, "iface")), text(get(o, "cidr")));
        format!("This node holds {oc} on {oi}, but the config expects {cidr}; the prefix differs. Replace it: scapegoat net addr_del --iface {oi} --cidr {oc} --confirm, then scapegoat net addr_add --iface {oi} --cidr {cidr} --confirm")
    } else {
        format!(
            "This node should hold {cidr} on the interface toward the sensor (the sensor learns our address from our keepalives). Add it: scapegoat net addr_add --iface {} --cidr {cidr} --confirm",
            sensor_iface_choice(ifaces, &toward_sensor(ifaces, session_results, &[]))
        )
    };
    res["hints"] = json!([hint]);
    res
}

/// Interfaces that evidently face the sensor.
fn toward_sensor(ifaces: &Value, session_results: &Value, expected_on: &[String]) -> Vec<String> {
    let names: Vec<String> = ifaces.as_array().cloned().unwrap_or_default().iter().map(|i| text(get(i, "name"))).collect();
    let mut found: Vec<String> = expected_on.to_vec();
    let results = session_results.as_array().cloned().unwrap_or_default();
    for s in &results {
        for p in s.get("peers").and_then(Value::as_array).cloned().unwrap_or_default() {
            for m in p.get("same_subnet").and_then(Value::as_array).cloned().unwrap_or_default() {
                found.push(text(get(&m, "iface")));
            }
        }
    }
    for s in &results {
        for p in s.get("peers").and_then(Value::as_array).cloned().unwrap_or_default() {
            let r = p.get("route").cloned().unwrap_or(json!({}));
            if let Some(ri) = r.get("iface").filter(|v| v.is_string()).map(text) {
                if names.contains(&ri) && !crate::config::truthy(r.get("gateway")) && !is_virtual(&ri) {
                    found.push(ri);
                }
            }
        }
    }
    dedupe(found.into_iter().filter(|n| names.contains(n)).collect())
}

/// '<iface> has no carrier' for the interface(s) that should face the sensor.
pub fn carrier_hints(ifaces: &Value, session_results: &Value, expected_on: &[String]) -> Vec<String> {
    let idx = iface_index(ifaces);
    let mut facing = toward_sensor(ifaces, session_results, expected_on);
    if facing.is_empty() {
        let wired: Vec<&(String, Value)> = idx.iter().filter(|(n, _)| is_wired(n)).collect();
        if !wired.is_empty() && !wired.iter().any(|(_, i)| i.get("carrier") == Some(&json!(true))) {
            facing = wired.iter().map(|(n, _)| n.clone()).collect();
        }
    }
    facing
        .iter()
        .filter(|n| idx_get(&idx, n).is_some_and(|i| i.get("carrier") == Some(&json!(false))))
        .map(|n| no_carrier_hint(n))
        .collect()
}

pub fn session_ports(config: &Value) -> Vec<i64> {
    let mut ports: Vec<i64> = vec![];
    for (_, s) in sessions_of(config) {
        if let Ok((_, Some(p))) = split_hostport(&get(&s, "local").clone()) {
            ports.push(p);
        }
        for (_, p) in session_peers(&s).0 {
            if let Some(p) = p {
                ports.push(p);
            }
        }
    }
    ports.sort();
    ports.dedup();
    if ports.is_empty() {
        vec![47000]
    } else {
        ports
    }
}

#[allow(clippy::too_many_arguments)]
fn sessions(
    host: &dyn Host,
    config: &Value,
    ifaces: &Value,
    neigh: &Value,
    dl: &Deadline,
    fw: &Value,
    mode: &str,
    routes_: &Value,
) -> Value {
    let expected = expected_address(config);
    let default_srcs = default_route_sources(routes_, ifaces);
    let listeners = udp_listeners(host, dl).unwrap_or_else(|e| json!({"error": e}));
    let mut result = vec![];
    for (sid, scfg) in sessions_of(config) {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            analyze_session(host, &sid, &scfg, ifaces, neigh, &listeners, fw, dl, expected, mode, &default_srcs)
        }));
        result.push(r.unwrap_or_else(|_| json!({"id": sid, "error": "analysis failed", "hints": []})));
    }
    Value::Array(result)
}

fn section(r: Result<Value, String>) -> Value {
    r.unwrap_or_else(|e| json!({"error": e}))
}

/// Full read-only picture. Never fails. Bounded to about 5 seconds.
pub fn snapshot(host: &dyn Host, config: &Value) -> Value {
    let dl = Deadline::new(5.0);
    let mut snap = json!({"host": host_info(host)});
    snap["interfaces"] = section(interfaces(host, &dl));
    snap["neighbors"] = section(neighbors(host, &dl));
    snap["routes"] = section(routes(host, &dl));
    let ifaces = if snap["interfaces"].is_array() { snap["interfaces"].clone() } else { json!([]) };
    let neigh = if snap["neighbors"].is_array() { snap["neighbors"].clone() } else { json!([]) };
    snap["firewall"] = firewall(host, &session_ports(config), &dl);
    snap["topology"] = topology(host, config, &ifaces, &dl);
    let mode = snap["topology"].get("mode").map(text).unwrap_or("same-lan".into());
    let routes_ = if snap["routes"].is_array() { snap["routes"].clone() } else { json!([]) };
    snap["sessions"] = sessions(host, config, &ifaces, &neigh, &dl, &snap["firewall"].clone(), &mode, &routes_);
    snap["expected_local"] = expected_local(config, &ifaces, &snap["sessions"]);
    let el = snap["expected_local"].clone();
    snap["expected_local_address"] = if el.is_null() {
        Value::Null
    } else if el.get("cidr").is_some() {
        json!({"cidr": el["cidr"], "present_on": el.get("on").and_then(Value::as_array).and_then(|a| a.first().cloned()).unwrap_or(Value::Null)})
    } else {
        el.clone()
    };
    let expected_on: Vec<String> = el.get("on").and_then(Value::as_array).map(|a| a.iter().map(text).collect()).unwrap_or_default();
    let mut hints = carrier_hints(&ifaces, &snap["sessions"], &expected_on);
    hints.extend(el.get("hints").and_then(Value::as_array).cloned().unwrap_or_default().iter().map(text));
    for s in snap["sessions"].as_array().cloned().unwrap_or_default() {
        hints.extend(s.get("hints").and_then(Value::as_array).cloned().unwrap_or_default().iter().map(text));
    }
    snap["hints"] = json!(dedupe(hints));
    snap
}

// ---- probes -------------------------------------------------------------------------------
/// One tcpdump -nn line, or None for lines that are not packets.
pub fn parse_tcpdump_line(line: &str) -> Option<Value> {
    let line = line.trim_end();
    let toks: Vec<&str> = line.split_whitespace().collect();
    let t0 = toks.first()?;
    let time_ok = {
        let b = t0.as_bytes();
        let clock = t0.split(':').collect::<Vec<_>>();
        (clock.len() == 3
            && (1..=2).contains(&clock[0].len())
            && clock[0].chars().all(|c| c.is_ascii_digit())
            && clock[1].len() == 2
            && clock[1].chars().all(|c| c.is_ascii_digit())
            && {
                let (s, f) = clock[2].split_once('.').unwrap_or(("", ""));
                s.len() == 2 && s.chars().all(|c| c.is_ascii_digit()) && !f.is_empty() && f.chars().all(|c| c.is_ascii_digit())
            })
            || (b.contains(&b'.') && {
                let (a, f) = t0.split_once('.').unwrap();
                !a.is_empty() && a.chars().all(|c| c.is_ascii_digit()) && !f.is_empty() && f.chars().all(|c| c.is_ascii_digit())
            })
    };
    if !time_ok || !line[t0.len()..].starts_with(char::is_whitespace) {
        return None;
    }
    let proto = |t: &str| t == "IP" || t == "IP6" || t == "ARP";
    let iface_ok = |t: &str| !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    // (index of the protocol token, iface/dir if present); the regex tries the iface form first
    let mut tries: Vec<(usize, Option<(String, String)>)> = vec![];
    if toks.len() > 3 && iface_ok(toks[1]) && proto(toks[3]) {
        tries.push((3, Some((toks[1].to_string(), toks[2].to_string()))));
    }
    if toks.len() > 1 && proto(toks[1]) {
        tries.push((1, None));
    }
    for (pi, ifd) in tries {
        let (Some(src), Some(gt), Some(dtok)) = (toks.get(pi + 1), toks.get(pi + 2), toks.get(pi + 3)) else { continue };
        if *gt != ">" {
            continue;
        }
        let Some(colon) = dtok.char_indices().skip(1).find(|(_, c)| *c == ':').map(|(i, _)| i) else { continue };
        let dst_raw = &dtok[..colon];
        // the rest: everything after that colon in the line, leading spaces dropped
        let dpos = line.find(&format!(" {dtok}")).map(|p| p + 1).unwrap_or(0);
        let rest = line[dpos + colon + 1..].trim_start();
        let icmp = rest.starts_with("ICMP");
        let split = |t: &str| -> (String, Value) {
            match t.rsplit_once('.') {
                Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                    (h.to_string(), json!(p.parse::<i64>().unwrap_or(0)))
                }
                _ => (t.to_string(), Value::Null),
            }
        };
        let ((s, sp), (d, dp)) =
            if icmp { ((src.to_string(), Value::Null), (dst_raw.to_string(), Value::Null)) } else { (split(src), split(dst_raw)) };
        let length = rest.find("length").and_then(|i| {
            let after = rest[i + 6..].trim_start_matches([':', ' ', '\t']);
            if after.len() == rest[i + 6..].len() {
                return None;
            }
            let n: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            n.parse::<i64>().ok()
        });
        let mut pkt = json!({"time": t0, "src": s, "src_port": sp, "dst": d, "dst_port": dp, "length": length});
        if sp.is_null() && dp.is_null() {
            pkt["icmp"] = json!(rest.trim());
        }
        if let Some((i, d)) = ifd {
            pkt["iface"] = json!(i);
            pkt["direction"] = json!(d);
        }
        return Some(pkt);
    }
    None
}

pub fn parse_tcpdump(t: &str, max_packets: usize) -> Vec<Value> {
    let mut pkts = vec![];
    for line in t.lines() {
        if let Some(p) = parse_tcpdump_line(line) {
            pkts.push(p);
            if pkts.len() >= max_packets {
                break;
            }
        }
    }
    pkts
}

/// ICMP unreachable lines in tcpdump -nn output -> [{router, to, target, line}].
pub fn icmp_unreachable(t: &str) -> Vec<Value> {
    crate::traffic::icmp_unreachable(t)
        .into_iter()
        .map(|u| {
            let line = text(&u["line"]);
            let to = line
                .split(' ')
                .collect::<Vec<_>>()
                .windows(4)
                .find(|w| w[0] == "IP" && w[2] == ">")
                .map(|w| w[3].trim_end_matches(':').to_string())
                .unwrap_or_default();
            json!({"router": u["router"], "to": to, "target": u["target"], "line": line})
        })
        .collect()
}

pub fn unreachable_hints(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .map(|u| format!("The router {} cannot find the sensor at {}: the sensor link not enabled, wrong address, or the sensor not on that segment.", text(&u["router"]), text(&u["target"])))
        .collect()
}

fn find_num(out: &str, pat: impl Fn(&str) -> Option<(i64, i64)>) -> Option<(i64, i64)> {
    out.lines().find_map(pat)
}

/// ICMP echo. -> {ip, reachable, sent, received, rtt_avg_ms, output_tail, command, error?}
pub fn ping(host: &dyn Host, ip: &Value, count: &Value, timeout_s: &Value) -> V<Value> {
    let ip = validate_ip(ip)?;
    let count = validate_int(count, "count", 1, 20)?;
    let timeout_s = validate_int(timeout_s, "timeout_s", 1, 60)?;
    let v6 = ip.contains(':');
    let mut cmd: Vec<String> = if host.system() == "Darwin" {
        let mut c = vec![if v6 { "ping6" } else { "ping" }.to_string(), "-c".into(), count.to_string(), "-i".into(), "0.5".into()];
        if !v6 {
            c.extend(["-t".into(), timeout_s.to_string()]);
        }
        c
    } else {
        let mut c: Vec<String> = ["ping", "-n", "-c", &count.to_string(), "-i", "0.5", "-W", "1", "-w", &timeout_s.to_string()]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if v6 {
            c.insert(1, "-6".into());
        }
        c
    };
    cmd.push(ip.clone());
    let (rc, out, err) = host.run(&cmd, (timeout_s + 2) as f64);
    let counts = find_num(&out, |l| {
        let i = l.find(" packets transmitted, ")?;
        let sent: String = l[..i].chars().rev().take_while(|c| c.is_ascii_digit()).collect::<String>().chars().rev().collect();
        let rest = &l[i + " packets transmitted, ".len()..];
        let recv: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let after = &rest[recv.len()..];
        if !(after.starts_with(" received") || after.starts_with(" packets received")) {
            return None;
        }
        Some((sent.parse().ok()?, recv.parse().ok()?))
    });
    let avg = out.lines().find_map(|l| {
        let i = l.find("= ")?;
        let parts: Vec<&str> = l[i + 2..].split('/').collect();
        if parts.len() < 3 {
            return None;
        }
        let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.');
        let third: String = parts[2].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        (ok(parts[0]) && ok(parts[1]) && !third.is_empty()).then(|| parts[1].parse::<f64>().ok()).flatten()
    });
    let lines: Vec<String> = out.trim().lines().map(String::from).collect();
    let tail: Vec<String> = if lines.is_empty() { vec![String::new()] } else { lines[lines.len().saturating_sub(3)..].to_vec() };
    let (sent, received) = match counts {
        Some((s, r)) => (s, r),
        None => (count, 0),
    };
    let mut res = json!({"ip": ip, "reachable": received > 0, "sent": sent, "received": received, "rtt_avg_ms": avg, "output_tail": tail, "command": cmd});
    if [124, 126, 127].contains(&rc) || (counts.is_none() && !err.trim().is_empty()) {
        res["error"] = json!(err.trim());
    }
    Ok(res)
}

/// Watch UDP packets on a port for up to `seconds`. Read-only: listens, sends nothing.
pub fn capture(host: &dyn Host, port: &Value, seconds: &Value, iface: &Value, max_packets: &Value) -> V<Value> {
    let port = validate_port(port)?;
    let seconds = validate_int(seconds, "seconds", 1, 120)?;
    let max_packets = validate_int(max_packets, "max_packets", 1, 5000)?;
    let iface = match iface {
        Value::Null => None,
        Value::String(s) if s.is_empty() || s == "any" => None,
        other => Some(validate_iface(host, other, None)?),
    };
    let iface = iface.or_else(|| (host.system() != "Darwin").then(|| "any".to_string()));
    let mut cmd: Vec<String> = vec!["tcpdump".into(), "-nn".into(), "-l".into(), "-c".into(), max_packets.to_string()];
    if let Some(i) = &iface {
        cmd.extend(["-i".into(), i.clone()]);
    }
    cmd.extend(["udp".into(), "port".into(), port.to_string(), "or".into(), "icmp".into()]);
    if !host.have("tcpdump") {
        return Ok(json!({"packets": [], "count": 0, "command": cmd, "error": "tcpdump is not installed (apt install tcpdump)"}));
    }
    let (rc, out, err) = host.run(&cmd, seconds as f64);
    let pkts = parse_tcpdump(&out, max_packets as usize);
    let mut res = json!({"packets": pkts, "count": pkts.len(), "command": cmd, "seconds": seconds});
    let unreach = icmp_unreachable(&out);
    if !unreach.is_empty() {
        res["hints"] = json!(unreachable_hints(&unreach));
        res["icmp_unreachable"] = json!(unreach);
    }
    // 124 = our timeout fired: the normal way a capture ends.
    if rc != 0 && rc != 124 {
        let msg: Vec<&str> = err.trim().lines().filter(|l| !l.contains("listening on") && !l.contains("verbose output")).collect();
        let mut e = if msg.is_empty() { format!("tcpdump exit {rc}") } else { msg.join(" ") };
        if e.contains("ermission") || e.contains("Operation not permitted") {
            e.push_str(" (tcpdump needs root)");
        }
        res["error"] = json!(e);
    }
    if pkts.is_empty() && res.get("error").is_none() {
        res["note"] = json!(format!(
            "no UDP {port} packets seen in {seconds}s on {}: neither side is sending, or traffic is on another interface",
            iface.unwrap_or("default iface".into())
        ));
    }
    Ok(res)
}

/// Read-only reachability check for a UDP peer. Sends nothing to the peer's port.
pub fn udp_probe(host: &dyn Host, ip: &Value, port: &Value) -> V<Value> {
    let ip = validate_ip(ip)?;
    let port = validate_port(port)?;
    let dl = Deadline::new(4.0);
    let mut out = json!({"ip": ip, "port": port, "note": "read-only: nothing was sent. Use capture to see whether packets flow, and ping for ICMP reachability."});
    out["route"] = route_get(host, &ip, &dl).unwrap_or_else(|e| json!({"error": e}));
    let target = out["route"].get("gateway").filter(|v| crate::config::truthy(Some(v))).map(text).unwrap_or(ip.clone());
    out["neighbor"] = match neighbors(host, &dl) {
        Ok(Value::Array(a)) => a.into_iter().find(|n| sget(n, "ip").as_deref() == Some(&target)).unwrap_or(Value::Null),
        Ok(other) => other,
        Err(e) => json!({"error": e}),
    };
    out["same_subnet"] = match interfaces(host, &dl) {
        Ok(i) => json!(same_subnet_addresses(&i, &ip)),
        Err(e) => json!({"error": e}),
    };
    Ok(out)
}

/// A read-only probe by name with the request's arguments (only the ones it takes).
pub fn probe(host: &dyn Host, name: &str, args: &Map<String, Value>) -> Result<Value, String> {
    let a = |k: &str| args.get(k).cloned();
    let missing = |f: &str, k: &str| format!("{f}() missing 1 required positional argument: '{k}'");
    let r = match name {
        "ping" => {
            ping(host, &a("ip").ok_or_else(|| missing("ping", "ip"))?, &a("count").unwrap_or(json!(3)), &a("timeout_s").unwrap_or(json!(5)))
        }
        "capture" => capture(
            host,
            &a("port").ok_or_else(|| missing("capture", "port"))?,
            &a("seconds").unwrap_or(json!(10)),
            &a("iface").unwrap_or(Value::Null),
            &a("max_packets").unwrap_or(json!(200)),
        ),
        "udp_probe" => {
            let ip = a("ip").ok_or_else(|| missing("udp_probe", "ip"))?;
            let port = a("port").ok_or_else(|| missing("udp_probe", "port"))?;
            udp_probe(host, &ip, &port)
        }
        other => return Err(format!("scapegoat net has no {other}()")),
    };
    r.map_err(|e| e.0)
}

// ---- control ------------------------------------------------------------------------------
pub struct ActionDef {
    pub name: &'static str,
    pub label: &'static str,
    pub dangerous: bool,
    pub args: &'static [&'static str],
    pub description: &'static str,
}

pub const ACTIONS: [ActionDef; 8] = [
    ActionDef { name: "addr_add", label: "Add address", dangerous: true, args: &["iface", "cidr"], description: "Add an IP address with prefix to an interface (ip addr add <cidr> dev <iface>). Put scapegoat in the sensor's subnet." },
    ActionDef { name: "addr_del", label: "Remove address", dangerous: true, args: &["iface", "cidr"], description: "Remove an IP address from an interface (ip addr del <cidr> dev <iface>)." },
    ActionDef { name: "link_up", label: "Link up", dangerous: true, args: &["iface"], description: "Bring an interface administratively up (ip link set dev <iface> up)." },
    ActionDef { name: "link_down", label: "Link down", dangerous: true, args: &["iface"], description: "Take an interface down (ip link set dev <iface> down). Cuts every connection on it, including yours if you came in that way." },
    ActionDef { name: "neigh_flush", label: "Flush ARP", dangerous: true, args: &["iface"], description: "Forget learned neighbor/ARP entries on an interface (ip neigh flush dev <iface>), e.g. after the sensor was swapped." },
    ActionDef { name: "fw_allow", label: "Allow UDP port", dangerous: true, args: &["iface", "from_cidr", "port"], description: "Allow incoming UDP to a port from a network on an interface (ufw allow in on <iface> from <cidr> to any port <port> proto udp)." },
    ActionDef { name: "ping", label: "Ping", dangerous: false, args: &["ip", "count"], description: "Send ICMP echo to an address and report replies and round-trip time." },
    ActionDef { name: "capture", label: "Capture", dangerous: false, args: &["port", "seconds", "iface"], description: "Watch UDP packets on a port for a few seconds (tcpdump); sends nothing." },
];

static AUDIT: Mutex<VecDeque<Value>> = Mutex::new(VecDeque::new());

/// Newest last. Each entry: time, action, args, command, ok, returncode, message.
pub fn audit_log() -> Vec<Value> {
    AUDIT.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
}

pub fn audit_clear() {
    AUDIT.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

fn result(ok: bool, action: &str, command: Vec<String>, stdout: &str, stderr: &str, rc: Option<i32>, message: &str) -> Value {
    json!({"ok": ok, "action": action, "command": command, "stdout": stdout, "stderr": stderr, "returncode": rc, "message": message})
}

fn tail_chars(s: &str, n: usize) -> String {
    let c: Vec<char> = s.chars().collect();
    c[c.len().saturating_sub(n)..].iter().collect()
}

fn record(res: &Value, args: &Map<String, Value>) {
    let entry = json!({"time": local_time_z(), "action": res["action"],
        "args": args.iter().filter(|(k, _)| k.as_str() != "confirm").map(|(k, v)| (k.clone(), v.clone())).collect::<Map<String, Value>>(),
        "command": res["command"], "ok": res["ok"], "returncode": res["returncode"], "message": res["message"],
        "stdout": tail_chars(res["stdout"].as_str().unwrap_or(""), 2000), "stderr": tail_chars(res["stderr"].as_str().unwrap_or(""), 2000)});
    let mut a = AUDIT.lock().unwrap_or_else(|e| e.into_inner());
    if a.len() == 200 {
        a.pop_front();
    }
    a.push_back(entry);
}

/// Validate args and return the exact command list.
pub fn build_command(host: &dyn Host, name: &str, args: &Map<String, Value>) -> V<Vec<String>> {
    let need = |k: &str| -> V<Value> {
        match args.get(k) {
            None | Some(Value::Null) => inv(format!("{name} needs '{k}'")),
            Some(Value::String(s)) if s.is_empty() => inv(format!("{name} needs '{k}'")),
            Some(v) => Ok(v.clone()),
        }
    };
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    match name {
        "addr_add" | "addr_del" => {
            let iface = validate_iface(host, &need("iface")?, None)?;
            let cidr = validate_iface_cidr(&need("cidr")?)?;
            Ok(s(&["ip", "addr", if name == "addr_add" { "add" } else { "del" }, &cidr, "dev", &iface]))
        }
        "link_up" | "link_down" => {
            let iface = validate_iface(host, &need("iface")?, None)?;
            Ok(s(&["ip", "link", "set", "dev", &iface, if name == "link_up" { "up" } else { "down" }]))
        }
        "neigh_flush" => {
            let iface = validate_iface(host, &need("iface")?, None)?;
            Ok(s(&["ip", "neigh", "flush", "dev", &iface]))
        }
        "fw_allow" => {
            let iface = validate_iface(host, &need("iface")?, None)?;
            let net = validate_network(&need("from_cidr")?)?;
            let port = validate_port(&need("port")?)?;
            Ok(s(&["ufw", "allow", "in", "on", &iface, "from", &net, "to", "any", "port", &port.to_string(), "proto", "udp"]))
        }
        _ => inv(format!("unknown action {}", pyfmt::str_repr(name))),
    }
}

/// Run one action. -> {ok, action, command, stdout, stderr, returncode, message}
/// (ping/capture add 'result' with the probe's own result).
pub fn run(host: &dyn Host, name: &str, args: &Map<String, Value>, config: &Value) -> Value {
    let Some(spec) = ACTIONS.iter().find(|a| a.name == name) else {
        let known: Vec<&str> = ACTIONS.iter().map(|a| a.name).collect();
        let res =
            result(false, name, vec![], "", "", None, &format!("unknown action {}; known: {}", pyfmt::str_repr(name), known.join(", ")));
        record(&res, args);
        return res;
    };
    if !spec.dangerous {
        let a = |k: &str, d: Value| args.get(k).cloned().unwrap_or(d);
        let res = if name == "ping" {
            match validate_ip(&a("ip", Value::Null)).and_then(|ip| ping(host, &json!(ip), &a("count", json!(3)), &json!(5))) {
                Ok(r) => {
                    let msg = format!("{}: {}/{} replies", text(&r["ip"]), text(&r["received"]), text(&r["sent"]))
                        + &if r["rtt_avg_ms"].is_null() { String::new() } else { format!(", avg {} ms", text(&r["rtt_avg_ms"])) }
                        + &r.get("error").filter(|e| crate::config::truthy(Some(e))).map(|e| format!(" ({})", text(e))).unwrap_or_default();
                    let tail: Vec<String> = r["output_tail"].as_array().cloned().unwrap_or_default().iter().map(text).collect();
                    let cmd: Vec<String> = r["command"].as_array().cloned().unwrap_or_default().iter().map(text).collect();
                    let reach = r["reachable"] == json!(true);
                    let mut res = result(
                        reach,
                        name,
                        cmd,
                        &tail.join("\n"),
                        r.get("error").map(text).unwrap_or_default().as_str(),
                        Some(if reach { 0 } else { 1 }),
                        &msg,
                    );
                    res["result"] = r;
                    res
                }
                Err(e) => result(false, name, vec![], "", "", None, &format!("refused: {}", e.0)),
            }
        } else {
            match capture(host, &a("port", json!(47000)), &a("seconds", json!(10)), &a("iface", Value::Null), &a("max_packets", json!(200)))
            {
                Ok(r) => {
                    let has_err = r.get("error").is_some();
                    let msg = r
                        .get("error")
                        .filter(|e| crate::config::truthy(Some(e)))
                        .or_else(|| r.get("note").filter(|e| crate::config::truthy(Some(e))))
                        .map(text)
                        .unwrap_or(format!("{} packets", text(&r["count"])));
                    let cmd: Vec<String> = r["command"].as_array().cloned().unwrap_or_default().iter().map(text).collect();
                    let mut res = result(
                        !has_err,
                        name,
                        cmd,
                        "",
                        r.get("error").map(text).unwrap_or_default().as_str(),
                        Some(if has_err { 1 } else { 0 }),
                        &msg,
                    );
                    res["result"] = r;
                    res
                }
                Err(e) => result(false, name, vec![], "", "", None, &format!("refused: {}", e.0)),
            }
        };
        record(&res, args);
        return res;
    }
    // dangerous: validate first, so a bad argument is reported even when not allowed
    let cmd = match build_command(host, name, args) {
        Ok(c) => c,
        Err(e) => {
            let res = result(false, name, vec![], "", "", None, &format!("refused: {}", e.0));
            record(&res, args);
            return res;
        }
    };
    if !truthy(config.get("allow_net_control")) {
        let res = result(false, name, cmd, "", "", None, "refused: network control is off on this node. Set allow_net_control = true in /etc/scapegoat/scapegoat.toml and restart scapegoat to allow it.");
        record(&res, args);
        return res;
    }
    if !truthy(args.get("confirm")) {
        let msg = format!("refused: {} changes this node's network. Re-run with confirm (--confirm) to run: {}", spec.label, cmd.join(" "));
        let res = result(false, name, cmd, "", "", None, &msg);
        record(&res, args);
        return res;
    }
    if !host.have(&cmd[0]) {
        let msg = format!("{} is not installed on this node", cmd[0]);
        let res = result(false, name, cmd, "", "", Some(127), &msg);
        record(&res, args);
        return res;
    }
    let (rc, out, err) = host.run(&cmd, 10.0);
    let ok = rc == 0;
    let mut msg = if ok {
        format!("done: {}", cmd.join(" "))
    } else {
        format!("failed (exit {rc}): {}", if err.is_empty() { out.trim() } else { err.trim() })
    };
    if !ok && (err.contains("Operation not permitted") || err.contains("need to be root")) {
        msg.push_str(" — scapegoat must run as root to change the network");
    }
    let res = result(ok, name, cmd, &out, &err, Some(rc), &msg);
    record(&res, args);
    res
}
