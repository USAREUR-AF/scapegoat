// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! This node's own addresses, each with a plain role label. Read-only and fast.
//!
//! Linux: `ip -j addr` and `ip -j route` only, cached 2 s. macOS (development): ifconfig and
//! `route -n get default`. Billie identity is read from files when they are readable.
//! Also the one-line check of `expected_local_address` (cached 10 s).

use crate::config::{truthy, Config};
use crate::ipnet::IfAddr;
use serde_json::{json, Map, Value};
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

pub const CACHE_S: f64 = 2.0;
pub const BILLIE_IDENTITY: &str = "/etc/billie/identity/node.yml";
pub const BILLIE_FABRIC: &str = "/etc/billie/zenoh/fabric.json";
pub const ROLE_ORDER: [&str; 7] = ["sensor LAN", "NetBird mesh", "wired", "Wi-Fi", "Billie containers", "other", "loopback"];

type Row = Map<String, Value>;

pub fn which(cmd: &str) -> bool {
    std::env::var("PATH").unwrap_or_default().split(':').any(|d| std::path::Path::new(d).join(cmd).is_file())
}

fn run(args: &[&str]) -> String {
    Command::new(args[0]).args(&args[1..]).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
}

fn obj(v: Value) -> Row {
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

// ------------------------------------------------------------------ parsing (testable)
/// `ip -j addr` -> [{iface, cidr, ip, family, link, cable}].
pub fn parse_ip_addr(text: &str) -> Vec<Row> {
    let data: Value = serde_json::from_str(if text.trim().is_empty() { "[]" } else { text }).unwrap_or(json!([]));
    let mut rows = vec![];
    for i in data.as_array().cloned().unwrap_or_default() {
        let flags: Vec<String> = i
            .get("flags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let oper = i.get("operstate").and_then(Value::as_str).unwrap_or("").to_uppercase();
        let admin_up = flags.iter().any(|f| f == "UP");
        let cable = if flags.iter().any(|f| f == "LOWER_UP") {
            Some(true)
        } else if flags.iter().any(|f| f == "NO-CARRIER") || oper == "DOWN" {
            Some(false)
        } else {
            None
        };
        let link = if admin_up && (cable == Some(true) || oper == "UP" || oper == "UNKNOWN") {
            "up"
        } else if !admin_up {
            "down"
        } else {
            "no cable"
        };
        let name = i.get("ifname").and_then(Value::as_str).unwrap_or("?").to_string();
        for a in i.get("addr_info").and_then(Value::as_array).cloned().unwrap_or_default() {
            let (Some(local), Some(p)) = (a.get("local").and_then(Value::as_str), a.get("prefixlen").and_then(Value::as_u64)) else {
                continue;
            };
            let Some(ifc) = IfAddr::parse(&format!("{local}/{p}")) else { continue };
            rows.push(obj(json!({
                "iface": name, "cidr": ifc.to_string(), "ip": ifc.ip.to_string(),
                "family": if ifc.is_v4() { "ipv4" } else { "ipv6" }, "link": link, "cable": cable,
            })));
        }
    }
    rows
}

/// `ip -j route` -> default routes [{iface, gateway, metric, src}], lowest metric first.
pub fn parse_ip_route(text: &str) -> Vec<Row> {
    let data: Value = serde_json::from_str(if text.trim().is_empty() { "[]" } else { text }).unwrap_or(json!([]));
    let mut out: Vec<Row> = vec![];
    for r in data.as_array().cloned().unwrap_or_default() {
        if r.get("dst").and_then(Value::as_str) == Some("default") {
            out.push(obj(json!({
                "iface": r.get("dev").cloned().unwrap_or(Value::Null),
                "gateway": r.get("gateway").cloned().unwrap_or(Value::Null),
                "metric": r.get("metric").cloned().unwrap_or(json!(0)),
                "src": r.get("prefsrc").cloned().unwrap_or(Value::Null),
            })));
        }
    }
    out.sort_by_key(|r| r["metric"].as_i64().unwrap_or(0));
    out
}

pub fn parse_ifconfig(text: &str) -> Vec<Row> {
    let mut rows = vec![];
    let (mut iface, mut up, mut active, mut pending): (String, bool, Option<bool>, Vec<Row>) = ("?".into(), false, None, vec![]);
    let close = |pending: &mut Vec<Row>, up: bool, active: Option<bool>, rows: &mut Vec<Row>| {
        for mut r in pending.drain(..) {
            r.insert("cable".into(), json!(active));
            let link = if up && active != Some(false) {
                "up"
            } else if !up {
                "down"
            } else {
                "no cable"
            };
            r.insert("link".into(), json!(link));
            rows.push(r);
        }
    };
    for line in text.lines() {
        if let Some((name, rest)) = line.split_once(": flags=") {
            if !name.is_empty()
                && !name.starts_with(char::is_whitespace)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
            {
                if let (Some(a), Some(b)) = (rest.find('<'), rest.find('>')) {
                    if rest[..a].chars().all(|c| c.is_ascii_digit()) {
                        close(&mut pending, up, active, &mut rows);
                        iface = name.to_string();
                        up = rest[a + 1..b].split(',').any(|f| f == "UP");
                        active = None;
                        continue;
                    }
                }
            }
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        for w in toks.windows(4) {
            if w[0] == "inet" && w[2] == "netmask" && w[3].starts_with("0x") {
                if let Ok(m) = u32::from_str_radix(&w[3][2..], 16) {
                    if let Some(ifc) = IfAddr::parse(&format!("{}/{}", w[1], m.count_ones())) {
                        pending.push(obj(json!({"iface": iface, "cidr": ifc.to_string(), "ip": ifc.ip.to_string(), "family": "ipv4"})));
                    }
                }
            }
            if w[0] == "inet6" && w[2] == "prefixlen" {
                let a = w[1].split('%').next().unwrap_or("");
                if let Some(ifc) = IfAddr::parse(&format!("{a}/{}", w[3])) {
                    pending.push(obj(json!({"iface": iface, "cidr": ifc.to_string(), "ip": ifc.ip.to_string(), "family": "ipv6"})));
                }
            }
        }
        let t = line.trim_start();
        if line.starts_with(char::is_whitespace) {
            if let Some(st) = t.strip_prefix("status: ") {
                active = Some(st.split_whitespace().next() == Some("active"));
            }
        }
    }
    close(&mut pending, up, active, &mut rows);
    rows
}

fn mesh_net() -> IfAddr {
    IfAddr::parse("100.64.0.0/10").unwrap()
}

pub fn role_of(row: &Row, sensor_ips: &[String], expected: &str) -> &'static str {
    let iface = row["iface"].as_str().unwrap_or("");
    let ip = IfAddr::parse(row["cidr"].as_str().unwrap_or("")).unwrap();
    if ip.ip.is_loopback() || iface.starts_with("lo") {
        return "loopback";
    }
    if !expected.is_empty() && IfAddr::parse(expected) == Some(ip) {
        return "sensor LAN";
    }
    for r in sensor_ips {
        if let Ok(a) = r.parse::<IpAddr>() {
            if ip.contains(&a) && ip.prefix > 0 {
                return "sensor LAN";
            }
        }
    }
    if iface == "wt0" || (ip.is_v4() && mesh_net().contains(&ip.ip)) {
        return "NetBird mesh";
    }
    if iface.starts_with("podman") {
        return "Billie containers";
    }
    if iface.starts_with("wl") {
        return "Wi-Fi";
    }
    if iface.starts_with("eth") || iface.starts_with("en") {
        return "wired";
    }
    "other"
}

pub fn read_billie(identity_path: &str, fabric_path: &str) -> Value {
    let mut out = Map::new();
    if let Ok(text) = std::fs::read_to_string(identity_path) {
        for line in text.lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix("node_handle") {
                if let Some(v) = rest.trim_start().strip_prefix(':') {
                    let v = v.trim_start().trim_start_matches(['\'', '"']);
                    let val: String = v.chars().take_while(|c| !"'\"#".contains(*c) && !c.is_whitespace()).collect();
                    if !val.is_empty() {
                        out.insert("node_handle".into(), json!(val));
                        break;
                    }
                }
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(fabric_path) {
        if let Ok(fab) = serde_json::from_str::<Value>(&text) {
            let mut stack = vec![fab];
            while let Some(d) = stack.pop() {
                if let Value::Object(m) = d {
                    for k in ["billie_fabric_prefix", "billie_fabric_endpoint", "node_handle"] {
                        if let Some(v) = m.get(k) {
                            if !out.contains_key(k) && (v.is_string() || (v.is_number() && !v.is_f64())) {
                                out.insert(k.into(), v.clone());
                            }
                        }
                    }
                    stack.extend(m.values().filter(|v| v.is_object()).cloned());
                }
            }
        }
    }
    if out.is_empty() {
        Value::Null
    } else {
        Value::Object(out)
    }
}

pub fn build(
    rows: &[Row],
    defaults: &[Row],
    sensor_ips: &[String],
    expected: &str,
    hostname: &str,
    billie: Value,
    include_loopback: bool,
) -> Value {
    // Which address carries each default route: its src, else the first IPv4 address on its
    // interface. The lowest metric is THE default route; others are backups.
    let mut route_note: Vec<((String, String), String)> = vec![];
    for (n, d) in defaults.iter().enumerate() {
        let diface = d["iface"].as_str().unwrap_or("").to_string();
        let src = d["src"].as_str().map(String::from).filter(|s| !s.is_empty()).or_else(|| {
            rows.iter()
                .find(|r| r["iface"].as_str() == Some(&diface) && r["family"] == "ipv4")
                .map(|r| r["ip"].as_str().unwrap_or("").to_string())
        });
        if let Some(src) = src {
            let key = (diface.clone(), src);
            if !route_note.iter().any(|(k, _)| *k == key) {
                let note = if n == 0 {
                    "default route".to_string()
                } else {
                    format!("backup default (metric {})", d.get("metric").map(crate::pyfmt::str).unwrap_or("?".into()))
                };
                route_note.push((key, note));
            }
        }
    }
    let mut out: Vec<Row> = vec![];
    let mut hidden = 0;
    for r in rows {
        let Some(ifc) = IfAddr::parse(r["cidr"].as_str().unwrap_or("")) else { continue };
        if r["family"] == "ipv6" && ifc.is_link_local() {
            continue;
        }
        let role = role_of(r, sensor_ips, expected);
        if role == "loopback" && !include_loopback {
            hidden += 1;
            continue;
        }
        let key = (r["iface"].as_str().unwrap_or("").to_string(), r["ip"].as_str().unwrap_or("").to_string());
        let note = route_note.iter().find(|(k, _)| *k == key).map(|(_, n)| n.clone()).unwrap_or_default();
        let mut row = r.clone();
        row.insert("role".into(), json!(role));
        row.insert("default_route".into(), json!(note == "default route"));
        row.insert("route_note".into(), json!(note));
        if role == "Wi-Fi" {
            row.insert("cable".into(), Value::Null); // no cable on Wi-Fi: link up/down only
        }
        out.push(row);
    }
    out.sort_by(|a, b| {
        let ka = (
            ROLE_ORDER.iter().position(|x| *x == a["role"]).unwrap_or(9),
            a["iface"].as_str().unwrap_or(""),
            a["family"].as_str().unwrap_or(""),
        );
        let kb = (
            ROLE_ORDER.iter().position(|x| *x == b["role"]).unwrap_or(9),
            b["iface"].as_str().unwrap_or(""),
            b["family"].as_str().unwrap_or(""),
        );
        ka.cmp(&kb)
    });
    json!({"hostname": hostname, "addresses": out,
           "default_route": defaults.first().cloned().map(Value::Object).unwrap_or(Value::Null),
           "loopback_hidden": hidden, "billie": billie})
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r != 0 {
        return "?".into();
    }
    let n = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..n]).to_string()
}

struct Cache {
    t: f64,
    key: String,
    val: Value,
}

static SNAP: Mutex<Option<Cache>> = Mutex::new(None);
static LOCAL: Mutex<Option<Cache>> = Mutex::new(None);

// ------------------------------------------------------------------ live
pub fn snapshot(config: &Config, include_loopback: bool) -> Value {
    let mut sensor_ips = vec![];
    for sc in &config.sessions {
        if let Ok(c) = sc.candidate_addrs() {
            sensor_ips.extend(c.into_iter().map(|a| a.0));
        }
    }
    let expected = config.expected_local_address.clone();
    let key = format!("{sensor_ips:?}|{expected}|{include_loopback}");
    let mut cache = SNAP.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = cache.as_ref() {
        if c.key == key && crate::clock::mono() - c.t < CACHE_S {
            return c.val.clone();
        }
    }
    let mut error = String::new();
    let (mut rows, mut defaults) = (vec![], vec![]);
    if which("ip") {
        rows = parse_ip_addr(&run(&["ip", "-j", "addr"]));
        defaults = parse_ip_route(&run(&["ip", "-j", "route"]));
    } else if which("ifconfig") {
        rows = parse_ifconfig(&run(&["ifconfig"]));
        let rt = run(&["route", "-n", "get", "default"]);
        let field = |name: &str| rt.lines().find_map(|l| l.trim().strip_prefix(name).map(|v| v.trim().to_string()));
        if let Some(i) = field("interface:") {
            defaults = vec![obj(json!({"iface": i, "gateway": field("gateway:"), "metric": 0, "src": null}))];
        }
    } else {
        error = "neither `ip` nor `ifconfig` is available".into();
    }
    let get = |k: &str, d: &str| config.get(k).filter(|v| truthy(Some(v))).map(crate::pyfmt::str).unwrap_or(d.into());
    let billie = read_billie(&get("billie_identity_path", BILLIE_IDENTITY), &get("billie_fabric_path", BILLIE_FABRIC));
    let mut val = build(&rows, &defaults, &sensor_ips, &expected, &hostname(), billie, include_loopback);
    if !error.is_empty() {
        val["error"] = json!(error);
    }
    *cache = Some(Cache { t: crate::clock::mono(), key, val: val.clone() });
    val
}

/// Every address on the node: (iface, address with prefix).
fn addresses() -> Result<Vec<(String, IfAddr)>, String> {
    let rows = if which("ip") {
        parse_ip_addr(&run(&["ip", "-j", "addr"]))
    } else if which("ifconfig") {
        parse_ifconfig(&run(&["ifconfig"])).into_iter().filter(|r| r["family"] == "ipv4").collect()
    } else {
        return Err("neither `ip` nor `ifconfig` is available".into());
    };
    Ok(rows.iter().filter_map(|r| Some((r["iface"].as_str()?.to_string(), IfAddr::parse(r["cidr"].as_str()?)?))).collect())
}

/// {cidr, present, on: [iface], other_prefix: [iface cidr], error?, text}, or None if unset.
pub fn check_expected(cidr: &str) -> Value {
    if cidr.is_empty() {
        return Value::Null;
    }
    let mut cache = LOCAL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = cache.as_ref() {
        if c.key == cidr && crate::clock::mono() - c.t < 10.0 {
            return c.val.clone();
        }
    }
    let val = match IfAddr::parse(cidr) {
        None => json!({"cidr": cidr, "present": false, "on": [], "other_prefix": [], "error": "not a valid address/prefix",
                       "text": format!("expected_local_address {} is not a valid address/prefix", crate::pyfmt::str_repr(cidr))}),
        Some(want) => match addresses() {
            Ok(addrs) => {
                let on: Vec<String> = addrs.iter().filter(|(_, a)| *a == want).map(|(i, _)| i.clone()).collect();
                let other: Vec<String> =
                    addrs.iter().filter(|(_, a)| a.ip == want.ip && *a != want).map(|(i, a)| format!("{i} {a}")).collect();
                let text = if !on.is_empty() {
                    format!("{want} present on {}", on.join(", "))
                } else if !other.is_empty() {
                    format!("{want} MISSING (this node has {}: prefix differs)", other.join(", "))
                } else {
                    format!("{want} MISSING on every interface (see: scapegoat net)")
                };
                json!({"cidr": want.to_string(), "present": !on.is_empty(), "on": on, "other_prefix": other, "text": text})
            }
            Err(e) => {
                json!({"cidr": want.to_string(), "present": null, "on": [], "other_prefix": [], "error": e, "text": format!("{want}: could not check ({e})")})
            }
        },
    };
    *cache = Some(Cache { t: crate::clock::mono(), key: cidr.into(), val: val.clone() });
    val
}
