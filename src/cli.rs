// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! scapegoat command line. Every command except `serve`, `sim` and `profiles` talks to the
//! running service over its local HTTP API. Verbs, flags (in both spellings), `--api` and
//! `--json` before or after the verb, exit codes and printed text are the Python version's.

use crate::config::truthy;
use crate::pyfmt;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{json, Map, Value};
use std::io::{BufRead, Write};
use std::time::Duration;

pub const DEFAULT_CONFIG: &str = "/etc/scapegoat/scapegoat.toml";
pub const NET_CONTROL: [&str; 6] = ["addr_add", "addr_del", "link_up", "link_down", "neigh_flush", "fw_allow"];

pub fn default_api() -> String {
    crate::extension::env("SCAPEGOAT_API").0.unwrap_or("http://127.0.0.1:8730".into())
}

/// --config, then $SCAPEGOAT_CONFIG, then /etc/scapegoat/scapegoat.toml (then any fallback a
/// site extension declares). -> (path, note).
pub fn resolve_config(explicit: Option<&str>) -> (String, String) {
    resolve_config_in(&crate::extension::current(), explicit, |n| std::env::var(n).ok(), |p| std::path::Path::new(p).exists())
}

/// [`resolve_config`] with the extension, environment and file check given.
pub fn resolve_config_in(
    ext: &crate::extension::Extension,
    explicit: Option<&str>,
    getenv: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> (String, String) {
    if let Some(e) = explicit {
        return (e.into(), String::new());
    }
    if let (Some(p), note) = ext.env("SCAPEGOAT_CONFIG", getenv) {
        return (p, note);
    }
    if !exists(DEFAULT_CONFIG) {
        for old in &ext.config_fallbacks {
            if exists(old) {
                return (old.clone(), ext.fallback_note(old, DEFAULT_CONFIG));
            }
        }
    }
    (DEFAULT_CONFIG.into(), String::new())
}

pub fn state_mark(state: &str) -> String {
    match state {
        "established" => "[OK]  established",
        "establishing" => "[..]  establishing",
        "handshaking" => "[>>]  handshaking",
        "degraded" => "[!]   degraded",
        "lost" => "[XX]  lost",
        "disabled" => "[--]  disabled",
        other => other,
    }
    .to_string()
}

#[derive(Debug)]
pub struct CliError(pub String);

type R<T> = Result<T, CliError>;

/// Where a command writes, and where it reads a typed confirmation from.
pub struct Io<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub input: &'a mut dyn BufRead,
}

impl Io<'_> {
    fn print(&mut self, s: &str) {
        let _ = writeln!(self.out, "{s}");
        let _ = self.out.flush();
    }
    fn write(&mut self, s: &str) {
        let _ = write!(self.out, "{s}");
        let _ = self.out.flush();
    }
}

fn user() -> String {
    for k in ["LOGNAME", "USER", "LNAME", "USERNAME"] {
        if let Ok(v) = std::env::var(k) {
            if !v.is_empty() {
                return v;
            }
        }
    }
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        if !pw.is_null() && !(*pw).pw_name.is_null() {
            return std::ffi::CStr::from_ptr((*pw).pw_name).to_string_lossy().to_string();
        }
    }
    String::new()
}

// ---------------------------------------------------------------- value helpers
fn g<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}

/// Python `str(v)`.
fn s(v: &Value) -> String {
    pyfmt::str(v)
}

/// `v.get(k) or default` as text.
fn s_or(v: &Value, k: &str, d: &str) -> String {
    let x = g(v, k);
    if truthy(Some(x)) {
        s(x)
    } else {
        d.into()
    }
}

fn arr(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

fn pad(text: &str, w: usize) -> String {
    format!("{text:<w$}")
}

/// Python `str.capitalize()`.
fn capitalize(t: &str) -> String {
    let mut c = t.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
        None => String::new(),
    }
}

/// Python `v[-n:]` of a list.
fn tail<T: Clone>(v: &[T], n: i64) -> Vec<T> {
    let len = v.len() as i64;
    let start = if n > 0 {
        (len - n).max(0)
    } else if n == 0 {
        0
    } else {
        (-n).min(len)
    };
    v[start as usize..].to_vec()
}

// ---------------------------------------------------------------- API client
pub fn call(api: &str, method: &str, path: &str, body: Option<&Value>, timeout: f64) -> R<Value> {
    let url = format!("{}{path}", api.trim_end_matches('/'));
    let data = body.map(pyfmt::dumps);
    let u = user();
    let headers = [("Content-Type", "application/json"), ("X-Scapegoat-Source", "cli"), ("X-Scapegoat-User", u.as_str())];
    match crate::http::request(method, &url, &headers, data.as_deref().map(str::as_bytes), Duration::from_secs_f64(timeout)) {
        Ok(r) if r.status < 400 => {
            if r.body.is_empty() {
                return Ok(Value::Null);
            }
            serde_json::from_slice(&r.body).map_err(|e| CliError(format!("bad JSON from {url}: {e}")))
        }
        Ok(r) => {
            let msg = serde_json::from_slice::<Value>(&r.body).ok().and_then(|v| v.get("error").cloned()).filter(|v| truthy(Some(v)));
            Err(CliError(msg.map(|m| s(&m)).unwrap_or(format!("HTTP {} from {url}", r.status))))
        }
        Err(e) => Err(CliError(format!(
            "cannot reach the scapegoat service at {api} ({}).\nIs it running?  Check: systemctl status scapegoat",
            e.0
        ))),
    }
}

// ---------------------------------------------------------------- formatting
pub fn age(v: &Value) -> String {
    match v.as_f64() {
        None => "never".into(),
        Some(x) if x >= 10.0 => format!("{x:.0}s ago"),
        Some(x) => format!("{x:.1}s ago"),
    }
}

pub fn table(rows: &[Vec<String>], headers: &[&str]) -> String {
    let n = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate().take(n) {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<String>| cells.iter().zip(&widths).map(|(c, w)| pad(c, *w)).collect::<Vec<_>>().join("  ");
    let mut out = vec![line(headers.iter().map(|h| h.to_string()).collect()), line(widths.iter().map(|w| "-".repeat(*w)).collect())];
    for r in rows {
        out.push(line(r.clone()));
    }
    out.join("\n")
}

fn peer_text(st: &Value) -> String {
    if truthy(st.get("locked")) {
        let seen = g(st, "peer_seen");
        let base = if truthy(Some(seen)) { s(seen) } else { s(g(st, "locked")) };
        return base + if truthy(st.get("lock_forced")) { " (locked, forced)" } else { "" };
    }
    let mut cands: Vec<String> = arr(g(st, "candidates")).iter().map(|c| s(g(c, "address"))).collect();
    if cands.is_empty() {
        cands = vec![s(g(st, "peer"))];
    }
    format!("probing {}", cands.join(", "))
}

pub fn print_expected(health: &Value) -> String {
    let el = g(health, "expected_local");
    if !truthy(Some(el)) {
        return String::new();
    }
    let mark = match g(el, "present") {
        Value::Bool(true) => "[OK]",
        Value::Bool(false) => "[!] ",
        _ => "[?] ",
    };
    format!("Node address: {mark} {}\n", s(g(el, "text")))
}

/// The 'This node' block: hostname, Billie identity, one row per address with its role.
pub fn print_node(node: &Value, indent: &str) -> String {
    if !truthy(Some(node)) {
        return String::new();
    }
    let mut out = String::new();
    let mut head = format!("{indent}This node: {}", node.get("hostname").map(s).unwrap_or("?".into()));
    let b = g(node, "billie");
    if truthy(b.get("node_handle")) {
        head += &format!("   Billie node {}", s(&b["node_handle"]));
    }
    if truthy(b.get("billie_fabric_prefix")) {
        head += &format!("   slot {}", s(&b["billie_fabric_prefix"]));
    }
    out += &format!("{head}\n");
    if truthy(b.get("billie_fabric_endpoint")) {
        out += &format!("{indent}  fabric endpoint {}\n", s(&b["billie_fabric_endpoint"]));
    }
    if truthy(node.get("error")) {
        out += &format!("{indent}  (addresses not available: {})\n", s(&node["error"]));
    }
    let mut rows = vec![];
    for a in arr(g(node, "addresses")) {
        let cable = match g(&a, "cable") {
            Value::Bool(true) => "cable",
            Value::Bool(false) => "NO CABLE",
            _ => "",
        };
        let link = a.get("link").map(s).unwrap_or("?".into()) + &if cable.is_empty() { String::new() } else { format!(", {cable}") };
        let note = if truthy(a.get("route_note")) {
            s(&a["route_note"])
        } else if truthy(a.get("default_route")) {
            "default route".into()
        } else {
            String::new()
        };
        rows.push(vec![s(g(&a, "role")), s(g(&a, "iface")), s(g(&a, "cidr")), link, note]);
    }
    if !rows.is_empty() {
        out += &format!("{indent}  {}\n", table(&rows, &["ROLE", "IFACE", "ADDRESS", "LINK", ""]).replace('\n', &format!("\n{indent}  ")));
    } else if !truthy(node.get("error")) {
        out += &format!("{indent}  (no addresses except loopback)\n");
    }
    out
}

pub fn topology_text(mode: &str) -> String {
    match mode {
        "routed" => "routed (sensor reached through a router; no sensor-subnet address on this node)",
        "same-lan" => "same-lan (this node is on the sensor's subnet)",
        "auto" => "auto (inferred from the route: see scapegoat net)",
        other => other,
    }
    .to_string()
}

pub fn identity_lines(ident: &Value) -> Vec<String> {
    if !truthy(Some(ident)) {
        return vec![];
    }
    let mut first = if truthy(ident.get("title")) {
        s(&ident["title"])
    } else if truthy(ident.get("hostname")) {
        s(&ident["hostname"])
    } else {
        "?".into()
    };
    if truthy(ident.get("role_note")) && truthy(ident.get("billie_node")) {
        first += &format!("   ({})", s(&ident["role_note"]));
    } else if truthy(ident.get("role_note")) {
        first = format!("{} · {}", s(g(ident, "hostname")), s(&ident["role_note"]));
    }
    let mut parts = vec![];
    if truthy(ident.get("billie_node")) {
        parts.push(format!("Billie node {}", s(&ident["billie_node"])));
    }
    let sees = arr(g(ident, "sensor_sees"));
    for r in &sees {
        parts.push(
            format!("sensor sees us at {}", s(g(r, "address")))
                + &if sees.len() > 1 { format!(" ({})", s(g(r, "session"))) } else { String::new() },
        );
    }
    if truthy(ident.get("mesh_address")) {
        parts.push(format!("mesh {}", s(&ident["mesh_address"])));
    }
    if truthy(ident.get("slot_short")) {
        parts.push(format!("slot {}", s(&ident["slot_short"])));
    }
    let mut out = vec![first];
    if !parts.is_empty() {
        out.push(format!("  {}", parts.join("  ·  ")));
    }
    out
}

/// C2 outputs block for `scapegoat status`.
pub fn print_outputs(o: &Value) -> String {
    if !truthy(Some(o)) || !truthy(o.get("outputs")) {
        return String::new();
    }
    let mut out = String::from("C2 outputs:");
    if truthy(o.get("error")) {
        out += &format!("  OFF: {}", s(&o["error"]));
    } else {
        out += &format!(
            "  {} tracks in, {} encode errors",
            o.get("tracks_in").map(s).unwrap_or("0".into()),
            o.get("encode_errors").map(s).unwrap_or("0".into())
        );
    }
    out.push('\n');
    for x in arr(&o["outputs"]) {
        let state = if truthy(x.get("enabled")) { "on " } else { "off" };
        let to: Vec<String> = arr(g(&x, "to")).iter().map(s).collect();
        out += &format!(
            "  [{state}] {} {} -> {}   sent {}, errors {}{}\n",
            pad(&s(g(&x, "name")), 10),
            pad(&s(g(&x, "format")), 15),
            to.join(", "),
            s(g(&x, "sent")),
            s(g(&x, "errors")),
            if truthy(x.get("last_error")) { format!(" ({})", s(&x["last_error"])) } else { String::new() }
        );
    }
    out
}

pub fn print_status(sessions: &[Value], health: &Value, node: &Value) -> String {
    let mut out = String::new();
    for line in identity_lines(g(health, "identity")) {
        out += &format!("{line}\n");
    }
    if truthy(Some(health)) && truthy(health.get("identity")) {
        out.push('\n');
    }
    out += &print_node(node, "");
    if truthy(Some(node)) {
        out.push('\n');
    }
    if truthy(Some(health)) && truthy(health.get("profile")) {
        out += &format!("Profile: {}\n", s(&health["profile"]));
    }
    if truthy(Some(health)) && truthy(health.get("topology")) {
        out += &format!("Topology: {}\n", topology_text(&s(&health["topology"])));
    }
    out += &print_expected(health);
    if truthy(Some(health)) {
        out.push('\n');
    }
    if sessions.is_empty() {
        out += "No sessions configured. Add a [sessions.<name>] table to the config.\n";
        return out;
    }
    let rows: Vec<Vec<String>> = sessions
        .iter()
        .map(|st| {
            vec![
                s(g(st, "id")),
                st.get("peer_kind").map(s).unwrap_or("?".into()),
                state_mark(&s(g(st, "state"))),
                peer_text(st),
                age(g(st, "last_rx_age_s")),
                age(g(st, "last_tx_age_s")),
                format!("{}/{}", s(g(st, "tx_datagrams")), s(g(st, "rx_datagrams"))),
                st.get("bad_datagrams").map(s).unwrap_or("0".into()),
            ]
        })
        .collect();
    out += &table(&rows, &["SESSION", "KIND", "STATE", "PEER", "LAST RX", "LAST TX", "TX/RX", "BAD"]);
    out.push('\n');
    for st in sessions {
        if truthy(st.get("error")) {
            out += &format!("\n{}: ERROR: {}\n", s(g(st, "id")), s(&st["error"]));
        }
        for line in attention_lines(st) {
            out += &format!("{}: {line}\n", s(g(st, "id")));
        }
    }
    out += &print_outputs(g(health, "outputs"));
    out
}

fn peer_status_text(ps: &Value) -> String {
    match ps {
        Value::Object(m) => m.values().filter(|v| truthy(Some(v))).map(s).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}

/// Lines an operator must see: what the device asks for, and problems.
pub fn attention_lines(st: &Value) -> Vec<String> {
    let mut out = vec![];
    let pr = g(st, "peer_request");
    if truthy(Some(pr)) {
        let noun = s_or(st, "device_noun", "device").to_uppercase();
        let mut line = format!("{noun} IS ASKING: {}", s(g(pr, "label")));
        let act = g(pr, "suggested_action");
        if truthy(pr.get("disabled_reason")) {
            line += &format!("  ({})", s(&pr["disabled_reason"]));
        } else if truthy(Some(act)) {
            let actname = s(act);
            let a = arr(g(st, "actions")).into_iter().find(|x| s(g(x, "name")) == actname).unwrap_or(json!({}));
            line += &(format!("  -> scapegoat action {} {actname}", s(g(st, "id")))
                + if truthy(a.get("dangerous")) { " --confirm" } else { "" });
            if truthy(Some(&a)) && !truthy(a.get("allowed")) {
                line += "  (needs allow_transmit_control = true)";
            }
        }
        out.push(line);
    }
    let probs = arr(g(st, "problems"));
    if let Some(p) = probs.first() {
        let more =
            if probs.len() > 1 { format!(" (+{} more: scapegoat status {})", probs.len() - 1, s(g(st, "id"))) } else { String::new() };
        out.push(format!("PROBLEM: {} (x{}){more}", s(g(p, "problem")), s(g(p, "count"))));
    }
    out
}

pub fn print_session(st: &Value) -> String {
    let mut out = String::new();
    let id = s(g(st, "id"));
    out += &format!("Session {id}  ({})   {}\n", s(g(st, "protocol")), kind_banner(st));
    out += &format!("  State:       {} for {}s\n", state_mark(&s(g(st, "state"))), s(g(st, "state_age_s")));
    let seen = if truthy(st.get("peer_seen")) { s(&st["peer_seen"]) } else { "nothing yet".into() };
    out += &format!("  Peer:        {}; seen from {seen}\n", peer_text(st));
    for c in arr(g(st, "candidates")) {
        let tag = if truthy(c.get("locked")) {
            "LOCKED"
        } else if truthy(c.get("probing")) {
            "probing"
        } else {
            "dropped"
        };
        out += &format!(
            "    candidate {} {} tx {} rx {}\n",
            pad(&s(g(&c, "address")), 22),
            pad(tag, 8),
            s(g(&c, "tx_counter")),
            s(g(&c, "rx_counter"))
        );
    }
    out += &format!("  Local:       {}   keepalive every {}s\n", s(g(st, "local")), s(g(st, "keepalive_interval_s")));
    out += &format!("  Counters:    our tx_counter {}, peer counter {}\n", s(g(st, "tx_counter")), s(g(st, "rx_counter")));
    out += &format!(
        "  Datagrams:   sent {}, received {} ({} messages, {} datagrams with several), bad {}, forwarded {} (one per {})\n",
        s(g(st, "tx_datagrams")),
        s(g(st, "rx_datagrams")),
        st.get("rx_messages").map(s).unwrap_or(s(g(st, "rx_datagrams"))),
        st.get("multi_message_datagrams").map(s).unwrap_or("0".into()),
        s(g(st, "bad_datagrams")),
        s(g(st, "forwarded")),
        st.get("forward_mode").map(s).unwrap_or("message".into())
    );
    for n in arr(g(st, "notes")) {
        let note = s(g(&n, "note"));
        let msgs: Vec<String> = arr(g(&n, "messages")).iter().map(s).collect();
        out += &format!(
            "  Note:        {} [{}] x{} (self-consistent; newer dictionary revision)\n",
            note.split(" (message is").next().unwrap_or(""),
            msgs.join(", "),
            s(g(&n, "count"))
        );
    }
    if truthy(st.get("peer_status")) {
        let label = capitalize(&s_or(st, "device_noun", "device")) + " says:";
        out += &format!(
            "  {}{} (last keepalive {})\n",
            pad(&label, 13),
            peer_status_text(&st["peer_status"]),
            age(g(&st["peer_status"], "age_s"))
        );
    }
    if truthy(st.get("error")) {
        out += &format!("  ERROR:       {}\n", s(&st["error"]));
    }
    let pr = g(st, "peer_request");
    if truthy(Some(pr)) {
        let mut nop = st.clone();
        nop["problems"] = json!([]);
        out += &format!("  {}  (x{}, last {})\n", attention_lines(&nop)[0], s(g(pr, "count")), age(g(pr, "last_seen_age_s")));
    }
    let ps = g(st, "protocol_status");
    let disp = g(ps, "display");
    for line in arr(g(disp, "lines")) {
        out += &format!("  {}\n", s(&line));
    }
    let ow = g(st, "owed_replies");
    if truthy(ow.get("answered")) || truthy(ow.get("missed")) || truthy(ow.get("waiting")) {
        out += &format!(
            "  Owed replies:   {} answered, {} missed, {} waiting\n",
            ow.get("answered").map(s).unwrap_or("0".into()),
            ow.get("missed").map(s).unwrap_or("0".into()),
            ow.get("waiting").map(s).unwrap_or("0".into())
        );
    }
    for t in arr(g(disp, "tables")) {
        out.push('\n');
        let rows: Vec<Vec<String>> =
            arr(g(&t, "rows")).iter().map(|row| arr(row).iter().map(|c| if c.is_null() { "-".into() } else { s(c) }).collect()).collect();
        let cols: Vec<String> = arr(g(&t, "columns")).iter().map(|c| s(c).to_uppercase()).collect();
        let colrefs: Vec<&str> = cols.iter().map(String::as_str).collect();
        out += &table(&rows, &colrefs);
        out.push('\n');
    }
    let probs = arr(g(st, "problems"));
    if !probs.is_empty() {
        out.push('\n');
        let rows: Vec<Vec<String>> = probs
            .iter()
            .map(|p| {
                vec![
                    s(g(p, "problem")),
                    arr(g(p, "messages")).iter().map(s).collect::<Vec<_>>().join(", "),
                    s(g(p, "count")),
                    age(g(p, "last_seen_age_s")),
                ]
            })
            .collect();
        out += &table(&rows, &["PROBLEM", "IN MESSAGES", "COUNT", "LAST SEEN"]);
        out.push('\n');
    }
    let rx = g(st, "rx_by_name").as_object().cloned().unwrap_or_default();
    let tx = g(st, "tx_by_name").as_object().cloned().unwrap_or_default();
    let mut names: Vec<String> = rx.keys().chain(tx.keys()).cloned().collect();
    names.sort();
    names.dedup();
    if !names.is_empty() {
        out.push('\n');
        let rows: Vec<Vec<String>> =
            names.iter().map(|n| vec![n.clone(), tx.get(n).map(s).unwrap_or("0".into()), rx.get(n).map(s).unwrap_or("0".into())]).collect();
        out += &table(&rows, &["MESSAGE", "SENT", "RECEIVED"]);
        out.push('\n');
    }
    out
}

pub fn print_events(events: &[Value]) -> String {
    if events.is_empty() {
        return "No events yet.\n".into();
    }
    events
        .iter()
        .map(|e| {
            format!(
                "{}  {}  {}  {}\n",
                s(g(e, "time")),
                pad(&e.get("source").map(s).unwrap_or_default(), 4),
                pad(&s(g(e, "kind")), 8),
                s(g(e, "message"))
            )
        })
        .collect()
}

fn emit(io: &mut Io, json_out: bool, obj: &Value, human: impl Fn(&Value) -> String) {
    if json_out {
        io.print(&pyfmt::dumps_indent(obj, 2));
    } else {
        io.write(&human(obj));
    }
}

fn arrow(d: &str) -> &'static str {
    match d {
        "tx" => "->",
        "rx" => "<-",
        "fwd" => "=>",
        "wire" => "~~",
        "dgram" => "<<",
        _ => "??",
    }
}

fn short(v: &Value, n: usize) -> String {
    let t = s(v);
    if t.chars().count() <= n {
        t
    } else {
        pyfmt::head(&t, n - 3) + "..."
    }
}

/// The protocol's own one-line summary (entry["summary"]), else the first six fields.
pub fn key_fields(e: &Value) -> String {
    if let Some(sm) = e.get("summary").filter(|v| !v.is_null()) {
        return s(sm);
    }
    match g(e, "fields") {
        Value::Object(f) => f.iter().take(6).map(|(k, v)| format!("{k}={}", short(v, 24))).collect::<Vec<_>>().join(" "),
        _ => String::new(),
    }
}

pub fn format_entry(e: &Value, fields: bool, hexdump: bool) -> String {
    let time = s_or(e, "time", "");
    let t: String = time.chars().skip(11).take(12).collect();
    let dir = s(g(e, "direction"));
    let who = if dir == "wire" {
        format!("{} > {}", e.get("src").map(s).unwrap_or("?".into()), e.get("dst").map(s).unwrap_or("?".into()))
    } else {
        e.get("peer").map(s).unwrap_or_default()
    };
    let mut line =
        format!("{t}  {} {}  {} {}", arrow(&dir), pad(&who, 21), pad(&e.get("name").map(s).unwrap_or("unknown".into()), 24), key_fields(e));
    if dir == "dgram" {
        let f = g(e, "fields");
        let msgs: Vec<String> = arr(g(f, "messages")).iter().map(s).collect();
        line = format!("{t}  << {}  datagram {} B = {}", pad(&who, 21), s(g(e, "length")), msgs.join(" + "))
            + &if truthy(f.get("padding_bytes")) { format!(" + {} B padding", s(&f["padding_bytes"])) } else { String::new() };
    }
    if truthy(e.get("notes")) {
        let notes: Vec<String> = arr(&e["notes"]).iter().map(|n| s(n).split(" (message is").next().unwrap_or("").to_string()).collect();
        line += &format!("  (note: {})", notes.join("; "));
    }
    let probs: Vec<String> = arr(g(e, "problems")).iter().map(s).collect();
    if !truthy(e.get("ok")) || !probs.is_empty() {
        let p = probs.join("; ");
        line += &format!("  !! {}", if p.is_empty() { "failed checks".into() } else { p });
    }
    let mut out = vec![line];
    if fields {
        if let Value::Object(f) = g(e, "fields") {
            for (k, v) in f {
                out.push(format!("      {k} = {}", s(v)));
            }
        }
    }
    if hexdump {
        let h: Vec<char> = s_or(e, "hex", "").chars().collect();
        for i in (0..h.len()).step_by(32) {
            let row: Vec<String> = (i..(i + 32).min(h.len())).step_by(2).map(|j| h[j..(j + 2).min(h.len())].iter().collect()).collect();
            out.push(format!("      {}", row.join(" ")));
        }
    }
    out.join("\n")
}

pub fn kind_banner(st: &Value) -> String {
    let k = g(st, "peer_kind");
    if k == "SIMULATOR" {
        return "*** SIMULATOR - not a real sensor ***".into();
    }
    let noun = s_or(st, "device_noun", "device");
    let ks = if k.is_null() { String::new() } else { s(k) };
    if truthy(st.get("peer_is_real")) || ks.starts_with("REAL ") {
        let rid = g(st, "peer_device_id");
        let wh = if truthy(st.get("peer_seen")) {
            s(&st["peer_seen"])
        } else if truthy(st.get("locked")) {
            s(&st["locked"])
        } else {
            String::new()
        };
        return format!("### {} {wh}", s(k))
            + &if rid.is_null() { String::new() } else { format!(" ({} ID {})", capitalize(&noun), s(rid)) }
            + " ###";
    }
    format!("(no {noun} has answered yet)")
}

// ---------------------------------------------------------------- commands
struct Ctx<'a, 'b> {
    io: &'a mut Io<'b>,
    api: String,
    json: bool,
}

fn show(c: &mut Ctx, m: &ArgMatches, entries: &[Value]) {
    let filter = m.get_one::<String>("filter").map(|f| f.to_lowercase());
    for e in entries {
        if let Some(f) = &filter {
            if !s_or(e, "name", "").to_lowercase().contains(f.as_str()) {
                continue;
            }
        }
        if c.json {
            c.io.print(&pyfmt::dumps(e));
        } else {
            c.io.print(&format_entry(e, m.get_flag("fields"), m.get_flag("hex")));
        }
    }
}

struct KindWatch {
    every: u64,
    n: u64,
    last: Option<(Value, Value, Value)>,
}

impl KindWatch {
    fn check(&mut self, c: &mut Ctx, session: &str, force: bool) {
        self.n += 1;
        if !force && self.n % self.every != 0 {
            return;
        }
        let Ok(st) = call(&c.api, "GET", &format!("/api/sessions/{session}"), None, 15.0) else { return };
        let key = (g(&st, "peer_kind").clone(), g(&st, "peer_seen").clone(), g(&st, "peer_device_id").clone());
        if self.last.as_ref() != Some(&key) {
            self.last = Some(key);
            if c.json {
                c.io.print(&pyfmt::dumps(&json!({"type": "peer_kind", "peer_kind": g(&st, "peer_kind"), "peer": g(&st, "peer_seen"), "peer_device_id": g(&st, "peer_device_id")})));
            } else {
                c.io.print(&format!("=== {} ===", kind_banner(&st)));
            }
        }
    }
}

fn cmd_watch(c: &mut Ctx, m: &ArgMatches) -> R<()> {
    let session = m.get_one::<String>("session").unwrap().clone();
    let base = format!("/api/sessions/{session}");
    let mut kinds = KindWatch { every: 4, n: 0, last: None };
    let once = m.get_flag("once");
    if m.get_flag("wire") {
        let seconds = *m.get_one::<f64>("seconds").unwrap();
        if !c.json {
            c.io.print(&format!("Capturing session {session}'s UDP port from the wire, {} s per round. Ctrl-C stops.", pyfmt::g(seconds)));
        }
        loop {
            kinds.check(c, &session, true);
            let r = call(&c.api, "GET", &format!("{base}/wire?seconds={}", pyfmt::g(seconds)), None, seconds + 20.0)?;
            if truthy(r.get("error")) {
                return Err(CliError(format!("wire capture: {}", s(&r["error"]))));
            }
            show(c, m, &arr(g(&r, "entries")));
            for h in arr(g(&r, "hints")) {
                c.io.print(&format!("!! {}", s(&h)));
            }
            if once || crate::signals::stopped() {
                return Ok(());
            }
        }
    }
    let last = *m.get_one::<i64>("last").unwrap();
    let r = call(&c.api, "GET", &format!("{base}/traffic?limit={}", last.max(1)), None, 15.0)?;
    if !c.json {
        c.io.print(&format!("Watching session {session} (-> sent, <- received, => forwarded). Ctrl-C stops."));
    }
    kinds.check(c, &session, true);
    let entries = arr(g(&r, "entries"));
    show(c, m, &if last > 0 { tail(&entries, last) } else { vec![] });
    let mut since = g(&r, "last_seq").as_i64().unwrap_or(0);
    while !once && !crate::signals::stopped() {
        std::thread::sleep(Duration::from_millis(500));
        let r = call(&c.api, "GET", &format!("{base}/traffic?since={since}&limit=500"), None, 15.0)?;
        kinds.check(c, &session, false);
        let entries = arr(g(&r, "entries"));
        show(c, m, &entries);
        if let Some(e) = entries.last() {
            since = g(e, "seq").as_i64().unwrap_or(since);
        } else if g(&r, "last_seq").as_i64().unwrap_or(0) < since {
            // service restarted or reset: start over
            since = 0;
        }
    }
    Ok(())
}

fn node(api: &str) -> Value {
    call(api, "GET", "/api/node", None, 5.0).unwrap_or(Value::Null)
}

fn cmd_status(c: &mut Ctx, m: &ArgMatches) -> R<()> {
    if let Some(sid) = m.get_one::<String>("session") {
        let st = call(&c.api, "GET", &format!("/api/sessions/{sid}"), None, 15.0)?;
        emit(c.io, c.json, &st, print_session);
        return Ok(());
    }
    let sessions = call(&c.api, "GET", "/api/sessions", None, 15.0)?;
    let health = call(&c.api, "GET", "/api/health", None, 15.0).unwrap_or(Value::Null);
    let nd = node(&c.api);
    if c.json {
        c.io.print(&pyfmt::dumps_indent(&json!({"health": health, "node": nd, "sessions": sessions}), 2));
    } else {
        c.io.write(&print_status(&arr(&sessions), &health, &nd));
    }
    Ok(())
}

fn cmd_events(c: &mut Ctx, m: &ArgMatches) -> R<()> {
    let n = *m.get_one::<i64>("n").unwrap();
    let ev = if let Some(sid) = m.get_one::<String>("session") {
        arr(&call(&c.api, "GET", &format!("/api/sessions/{sid}/events?n={n}"), None, 15.0)?)
    } else {
        let mut ev = vec![];
        for st in arr(&call(&c.api, "GET", "/api/sessions", None, 15.0)?) {
            let sid = s(g(&st, "id"));
            for mut e in arr(&call(&c.api, "GET", &format!("/api/sessions/{sid}/events?n={n}"), None, 15.0)?) {
                e["message"] = json!(format!("[{sid}] {}", s(g(&e, "message"))));
                ev.push(e);
            }
        }
        ev.extend(arr(&call(&c.api, "GET", "/api/events", None, 15.0)?));
        ev.sort_by(|a, b| g(a, "ts").as_f64().unwrap_or(0.0).total_cmp(&g(b, "ts").as_f64().unwrap_or(0.0)));
        tail(&ev, n)
    };
    emit(c.io, c.json, &Value::Array(ev), |v| print_events(&arr(v)));
    Ok(())
}

fn cmd_actions(c: &mut Ctx, m: &ArgMatches) -> R<()> {
    let sid = m.get_one::<String>("session").unwrap();
    let st = call(&c.api, "GET", &format!("/api/sessions/{sid}"), None, 15.0)?;
    emit(c.io, c.json, &st, |st| {
        let rows: Vec<Vec<String>> = arr(g(st, "actions"))
            .iter()
            .map(|a| {
                vec![
                    s(g(a, "name")) + &arr(g(a, "params")).iter().map(|p| format!(" <{}>", s(g(p, "name")))).collect::<String>(),
                    if truthy(a.get("dangerous")) { "LOCKED (--arm)".into() } else { String::new() },
                    if truthy(a.get("allowed")) { "yes".into() } else { "no (allow_transmit_control is false)".into() },
                    s(g(a, "description")),
                ]
            })
            .collect();
        table(&rows, &["ACTION", "", "ALLOWED", "WHAT IT DOES"]) + "\n"
    });
    Ok(())
}

/// Positional values in the action's parameter order, or name=value.
pub fn action_args(spec: &Value, values: &[String]) -> R<Map<String, Value>> {
    let params: Vec<String> = arr(g(spec, "params")).iter().map(|p| s(g(p, "name"))).collect();
    let mut out = Map::new();
    let mut pos = 0;
    for v in values {
        if let Some((k, val)) = v.split_once('=') {
            out.insert(k.replace('-', "_"), json!(val));
        } else {
            if pos >= params.len() {
                return Err(CliError(format!(
                    "{} takes {} value(s): {}",
                    s(g(spec, "name")),
                    params.len(),
                    if params.is_empty() { "none".to_string() } else { params.join(" ") }
                )));
            }
            out.insert(params[pos].clone(), json!(v));
            pos += 1;
        }
    }
    let missing: Vec<String> = arr(g(spec, "params"))
        .iter()
        .filter(|p| g(p, "default").is_null() && !out.contains_key(&s(g(p, "name"))))
        .map(|p| s(g(p, "name")))
        .collect();
    if !missing.is_empty() {
        return Err(CliError(format!("{} needs: {}", s(g(spec, "name")), missing.join(" "))));
    }
    Ok(out)
}

fn cmd_action(c: &mut Ctx, m: &ArgMatches) -> R<()> {
    let sid = m.get_one::<String>("session").unwrap().clone();
    let raw_name = m.get_one::<String>("name").unwrap().clone();
    let name = raw_name.replace('-', "_");
    let values: Vec<String> = m.get_many::<String>("values").map(|v| v.cloned().collect()).unwrap_or_default();
    let st = call(&c.api, "GET", &format!("/api/sessions/{sid}"), None, 15.0)?;
    let spec = arr(g(&st, "actions")).into_iter().find(|a| s(g(a, "name")) == name);
    let Some(spec) = spec else {
        // let the service say why (unknown, or hidden by the feature flag)
        call(&c.api, "POST", &format!("/api/sessions/{sid}/actions/{name}"), Some(&json!({})), 15.0)?;
        return Err(CliError(format!("no action named {}. List them: scapegoat actions {sid}", pyfmt::str_repr(&raw_name))));
    };
    let vals = action_args(&spec, &values)?;
    let base = format!("/api/sessions/{sid}");
    if !truthy(spec.get("dangerous")) {
        let r = call(&c.api, "POST", &format!("{base}/actions/{name}"), Some(&json!({"args": vals})), 15.0)?;
        emit(c.io, c.json, &r, |r| format!("Sent {} on {} ({} bytes).\n", s(g(r, "action")), s(g(r, "session")), s(g(r, "bytes"))));
        return Ok(());
    }
    // Commands the device: the safety latch. One command per arm.
    if !m.get_flag("arm") {
        let mut effect = s_or(&spec, "effect", &name);
        for (k, v) in &vals {
            effect = effect.replace(&format!("{{{k}}}"), &s(v));
        }
        let to_send = format!("To send it: scapegoat action {sid} {raw_name} {} --arm", values.join(" "));
        return Err(CliError(format!("{name} is locked. It would: {effect}.\n{}", to_send.trim_end())));
    }
    let a = call(&c.api, "POST", &format!("{base}/arm/{name}"), Some(&json!({"args": vals})), 15.0)?;
    c.io.print(&format!("ARMED for {} s: {}.", pyfmt::g(g(&a, "expires_in_s").as_f64().unwrap_or(0.0)), s(g(&a, "effect"))));
    let noun = a.get("device_noun").map(s).unwrap_or("device".into());
    let typed = match m.get_one::<String>("confirm") {
        Some(t) => t.clone(),
        None => {
            c.io.write(&format!("Type the {noun} ID ({}) to send it, anything else cancels: ", s(g(&a, "device_id"))));
            let mut line = String::new();
            let _ = c.io.input.read_line(&mut line);
            line.trim_end_matches(['\n', '\r']).to_string()
        }
    };
    if typed.trim() != s(g(&a, "device_id")) {
        call(&c.api, "POST", &format!("{base}/disarm/{name}"), Some(&json!({})), 15.0)?;
        return Err(CliError(format!("cancelled: the {noun} ID did not match. Re-locked.")));
    }
    let r = call(
        &c.api,
        "POST",
        &format!("{base}/actions/{name}"),
        Some(&json!({"args": vals, "token": g(&a, "token"), "confirm": typed.trim()})),
        15.0,
    )?;
    emit(c.io, c.json, &r, |r| format!("Sent {} on {}: {}. Re-locked.\n", s(g(r, "action")), s(g(r, "session")), s(g(r, "effect"))));
    Ok(())
}

fn cmd_lock(c: &mut Ctx, m: &ArgMatches) -> R<()> {
    let sid = m.get_one::<String>("session").unwrap();
    let peer = m.get_one::<String>("peer").unwrap();
    let r = call(&c.api, "POST", &format!("/api/sessions/{sid}/lock"), Some(&json!({"peer": peer})), 15.0)?;
    emit(c.io, c.json, &r, |r| {
        format!(
            "Session {} locked onto {}. `scapegoat reset {}` goes back to probing all candidates.\n",
            s(g(r, "id")),
            s(g(r, "locked")),
            s(g(r, "id"))
        )
    });
    Ok(())
}

fn cmd_profiles(c: &mut Ctx, m: &ArgMatches) {
    let dir = m.get_one::<String>("profiles_dir").cloned();
    let profs = Value::Array(crate::config::list_profiles(dir.as_deref()));
    emit(c.io, c.json, &profs, |p| {
        let p = arr(p);
        if p.is_empty() {
            return format!("No profiles found in {}\n", crate::config::profile_dirs(dir.as_deref()).join(", "));
        }
        let rows: Vec<Vec<String>> = p.iter().map(|x| vec![s(g(x, "name")), s(g(x, "description"))]).collect();
        table(&rows, &["PROFILE", "WHAT IT IS FOR"])
            + "\n\nUse one: put  profile = \"<name>\"  at the top of /etc/scapegoat/scapegoat.toml\n"
    });
}

fn cmd_lifecycle(c: &mut Ctx, cmd: &str, m: &ArgMatches) -> R<()> {
    let sid = m.get_one::<String>("session").unwrap();
    let r = call(&c.api, "POST", &format!("/api/sessions/{sid}/{cmd}"), Some(&json!({})), 15.0)?;
    emit(c.io, c.json, &r, |r| format!("{cmd}: session {} is now {}.\n", s(g(r, "id")), s(g(r, "state"))));
    Ok(())
}

/// Every `scapegoat net ... --confirm` command in a hint (Python `_FIX_RE.findall`).
fn find_fixes(h: &str) -> Vec<(usize, usize)> {
    let mut out = vec![];
    let mut i = 0;
    while let Some(p) = h[i..].find("scapegoat net ") {
        let start = i + p;
        let after = start + "scapegoat net ".len();
        let next = h[after..].chars().next();
        if next.is_none() || next.unwrap().is_whitespace() {
            i = after;
            continue;
        }
        let body_start = after + next.unwrap().len_utf8();
        match h[body_start..].find("--confirm") {
            Some(q) => {
                let end = body_start + q + "--confirm".len();
                out.push((start, end));
                i = end;
            }
            None => break,
        }
    }
    out
}

fn is_err(v: &Value) -> bool {
    v.is_object() && v.get("error").is_some()
}

fn yn(v: &Value) -> &'static str {
    match v {
        Value::Bool(true) => "yes",
        Value::Bool(false) => "no",
        _ => "?",
    }
}

/// Human view of the network snapshot. --json gives the raw snapshot.
pub fn print_net(snap: &Value) -> String {
    if !snap.is_object() {
        return format!("{}\n", s(snap));
    }
    let mut out = String::new();
    let hints = arr(g(snap, "hints"));
    if !hints.is_empty() {
        out += "FIX THESE FIRST\n";
        for (n, h) in hints.iter().enumerate() {
            let h = s(h);
            let fixes = find_fixes(&h);
            let mut text = String::new();
            let mut last = 0;
            for (a, b) in &fixes {
                text += &h[last..*a];
                text += "(command below)";
                last = *b;
            }
            text += &h[last..];
            out += &format!("  {}. {text}\n", n + 1);
            for (a, b) in &fixes {
                out += &format!("       {}\n", &h[*a..*b]);
            }
        }
        out.push('\n');
    } else {
        out += "No problems found by the network checks.\n\n";
    }
    let topo = g(snap, "topology");
    if topo.is_object() && truthy(topo.get("mode")) {
        out += &format!("Topology: {}; from {}\n", topology_text(&s(&topo["mode"])), topo.get("source").map(s).unwrap_or("?".into()));
        if truthy(topo.get("note")) {
            out += &format!("  note: {}\n", s(&topo["note"]));
        }
        out.push('\n');
    }
    let el = g(snap, "expected_local");
    if el.is_object() && truthy(el.get("cidr")) {
        if truthy(el.get("present")) {
            out += &format!(
                "Node address: [OK] {} present on {}\n",
                s(&el["cidr"]),
                arr(g(el, "on")).iter().map(s).collect::<Vec<_>>().join(", ")
            );
        } else {
            let other: Vec<String> =
                arr(g(el, "other_prefix")).iter().map(|o| format!("{} {}", s(g(o, "iface")), s(g(o, "cidr")))).collect();
            out += &format!(
                "Node address: [!]  {} MISSING{}\n",
                s(&el["cidr"]),
                if other.is_empty() { String::new() } else { format!(" (has {})", other.join(", ")) }
            );
        }
        out.push('\n');
    }
    let ifaces = g(snap, "interfaces");
    out += "INTERFACES\n";
    if is_err(ifaces) {
        out += &format!("  not available: {}\n", s(&ifaces["error"]));
    } else if let Value::Array(list) = ifaces {
        let mut rows = vec![];
        let mut hidden = 0;
        for i in list {
            let addrs: Vec<String> = arr(g(i, "addresses"))
                .iter()
                .filter(|a| truthy(a.get("cidr")) && !s(&a["cidr"]).to_lowercase().starts_with("fe80"))
                .map(|a| s(&a["cidr"]))
                .collect();
            if addrs.is_empty() && !(truthy(i.get("admin_up")) && truthy(i.get("carrier"))) {
                hidden += 1;
                continue;
            }
            let state = match g(i, "admin_up") {
                v if truthy(Some(v)) => "up",
                Value::Bool(false) => "down",
                _ => "?",
            };
            rows.push(vec![
                i.get("name").map(s).unwrap_or("?".into()),
                state.into(),
                yn(g(i, "carrier")).into(),
                if addrs.is_empty() { "-".into() } else { addrs.join(", ") },
            ]);
        }
        if !rows.is_empty() {
            out += &format!("  {}\n", table(&rows, &["IFACE", "ADMIN", "CABLE", "ADDRESSES"]).replace('\n', "\n  "));
        }
        if hidden > 0 {
            out += &format!("  ({hidden} more without addresses; --json shows all)\n");
        }
    }
    out.push('\n');
    let sessions = g(snap, "sessions");
    out += "SENSOR ADDRESSES\n";
    if is_err(sessions) {
        out += &format!("  not available: {}\n", s(&sessions["error"]));
    } else if let Value::Array(list) = sessions {
        let mut rows = vec![];
        let mut listen = vec![];
        for st in list {
            let sid = st.get("id").map(s).unwrap_or("?".into());
            if truthy(st.get("error")) {
                rows.push(vec![sid.clone(), "-".into(), "-".into(), "-".into(), format!("error: {}", s(&st["error"]))]);
                continue;
            }
            let peers = if truthy(st.get("peers")) {
                arr(&st["peers"])
            } else if truthy(st.get("peer_ip")) {
                vec![
                    json!({"ip": st["peer_ip"], "port": g(st, "peer_port"), "same_subnet": g(st, "same_subnet"), "route": g(st, "route"), "neighbor": g(st, "neighbor")}),
                ]
            } else {
                vec![]
            };
            for p in peers {
                let ss = arr(g(&p, "same_subnet"));
                let same = if ss.is_empty() {
                    "NO".to_string()
                } else {
                    "yes, ".to_string()
                        + &ss.iter().map(|m| format!("{} {}", s(g(m, "iface")), s(g(m, "cidr")))).collect::<Vec<_>>().join(", ")
                };
                let r = g(&p, "route");
                let route = if is_err(r) {
                    "error".to_string()
                } else {
                    format!("via {}", s_or(r, "iface", "?"))
                        + &if truthy(r.get("gateway")) { format!(" gw {}", s(&r["gateway"])) } else { String::new() }
                };
                let nb = g(&p, "neighbor");
                let stv = g(nb, "state");
                let stt = match stv {
                    Value::Array(a) => a.iter().map(s).collect::<Vec<_>>().join(" "),
                    Value::Null => String::new(),
                    v if !truthy(Some(v)) => String::new(),
                    v => s(v),
                };
                let neigh = stt + &if truthy(nb.get("mac")) { format!(" {}", s(&nb["mac"])) } else { String::new() };
                rows.push(vec![
                    sid.clone(),
                    format!("{}:{}", s(g(&p, "ip")), s(g(&p, "port"))),
                    same,
                    route,
                    if neigh.is_empty() { "?".into() } else { neigh },
                ]);
            }
            if let Value::Array(ls) = g(st, "listeners") {
                let w: Vec<String> = ls
                    .iter()
                    .map(|x| {
                        format!("{}:{}", s(g(x, "local")), s(g(x, "port")))
                            + &if truthy(x.get("process")) { format!(" ({})", s(&x["process"])) } else { String::new() }
                    })
                    .collect();
                listen.push(format!(
                    "  {sid}: UDP port {} listeners: {}",
                    st.get("local_port").map(s).unwrap_or("?".into()),
                    if w.is_empty() { "NONE".into() } else { w.join(", ") }
                ));
            }
        }
        if !rows.is_empty() {
            out += &format!("  {}\n", table(&rows, &["SESSION", "PEER", "SAME SUBNET", "ROUTE", "NEIGHBOR"]).replace('\n', "\n  "));
        }
        for l in listen {
            out += &format!("{l}\n");
        }
        for st in list {
            for n in arr(g(st, "notes")) {
                out += &format!("  note ({}): {}\n", st.get("id").map(s).unwrap_or("?".into()), s(&n));
            }
        }
    }
    out.push('\n');
    let fw = g(snap, "firewall");
    if fw.is_object() {
        let tool = s_or(fw, "tool", "none");
        let line = if truthy(fw.get("error")) {
            format!("{tool}: could not read ({})", s(&fw["error"]))
        } else if truthy(fw.get("note")) {
            format!("{tool}: {}", s(&fw["note"]))
        } else {
            let mut l = format!("{tool}: {}", if truthy(fw.get("active")) { "active" } else { "inactive" });
            if truthy(fw.get("default_incoming")) {
                l += &format!(", default incoming {}", s(&fw["default_incoming"]));
            }
            let rules: Vec<String> = arr(g(fw, "port_rules")).iter().map(s).collect();
            l += &format!(
                "; rules for the port: {}",
                if rules.is_empty() { "none".into() } else { rules.iter().take(4).cloned().collect::<Vec<_>>().join("; ") }
            );
            l
        };
        out += &format!("FIREWALL  {line}\n");
    }
    out
}

/// Human view of a ping / capture / control result; unknown shapes print as JSON.
pub fn print_net_result(r: &Value) -> String {
    if !r.is_object() {
        return format!("{}\n", s(r));
    }
    if r.get("reachable").is_some() {
        let rtt =
            if r.get("rtt_avg_ms").is_some_and(|v| !v.is_null()) { format!(", average {} ms", s(&r["rtt_avg_ms"])) } else { String::new() };
        let mut out = format!(
            "{}: {} ({}/{} replies{rtt})\n",
            s(g(r, "ip")),
            if truthy(r.get("reachable")) { "REACHABLE" } else { "NOT reachable" },
            r.get("received").map(s).unwrap_or("?".into()),
            r.get("sent").map(s).unwrap_or("?".into())
        );
        if truthy(r.get("error")) {
            out += &format!("  {}\n", s(&r["error"]));
        }
        return out;
    }
    if let Some(pk) = r.get("packets") {
        let mut out = format!(
            "{} packets in {} s\n",
            r.get("count").map(s).unwrap_or(arr(pk).len().to_string()),
            r.get("seconds").map(s).unwrap_or("?".into())
        );
        for p in arr(pk) {
            if p.is_object() {
                out += &format!(
                    "  {}  {} > {}  {} bytes\n",
                    p.get("time").map(s).unwrap_or_default(),
                    p.get("src").map(s).unwrap_or("?".into()),
                    p.get("dst").map(s).unwrap_or("?".into()),
                    p.get("length").map(s).unwrap_or("?".into())
                );
            } else {
                out += &format!("  {}\n", s(&p));
            }
        }
        if truthy(r.get("error")) {
            out += &format!("  problem: {}\n", s(&r["error"]));
        }
        return out;
    }
    if r.get("ok").is_some() && (r.get("command").is_some() || r.get("message").is_some()) {
        let what = if truthy(r.get("message")) {
            s(&r["message"])
        } else if truthy(r.get("action")) {
            s(&r["action"])
        } else {
            String::new()
        };
        let mut out = format!("{}{what}\n", if truthy(r.get("ok")) { "Done: " } else { "FAILED: " });
        let cmd = g(r, "command");
        if truthy(Some(cmd)) {
            let text = match cmd {
                Value::Array(a) => a.iter().map(s).collect::<Vec<_>>().join(" "),
                v => s(v),
            };
            out += &format!("  ran: {text}\n");
        }
        for k in ["stdout", "stderr"] {
            if truthy(r.get(k)) {
                out += &format!("  {k}: {}\n", s(&r[k]).trim().replace('\n', "\n          "));
            }
        }
        return out;
    }
    pyfmt::dumps_indent(r, 2) + "\n"
}

fn cmd_net(c: &mut Ctx, m: &ArgMatches) -> R<()> {
    let (act, sm) = match m.subcommand() {
        Some((a, sm)) => (a.to_string(), sm.clone()),
        None => ("show".to_string(), m.clone()),
    };
    if sm.get_flag("json") {
        c.json = true;
    }
    if let Some(a) = sm.get_one::<String>("api") {
        c.api = a.clone();
    }
    if act == "show" {
        let nd = node(&c.api);
        let snap = call(&c.api, "GET", "/api/net", None, 30.0)?;
        if c.json {
            let v = if let Value::Object(mut o) = snap.clone() {
                o.insert("node".into(), nd);
                Value::Object(o)
            } else {
                snap
            };
            c.io.print(&pyfmt::dumps_indent(&v, 2));
        } else {
            if truthy(Some(&nd)) {
                c.io.print("THIS NODE");
                c.io.write(&print_node(&nd, "  "));
                c.io.print("");
            }
            c.io.write(&print_net(&snap));
        }
        return Ok(());
    }
    let r = match act.as_str() {
        "ping" => call(
            &c.api,
            "POST",
            "/api/net/ping",
            Some(&json!({"ip": sm.get_one::<String>("ip"), "count": sm.get_one::<i64>("count")})),
            30.0,
        )?,
        "capture" => {
            let seconds = *sm.get_one::<i64>("seconds").unwrap();
            let mut body = json!({"port": sm.get_one::<i64>("port"), "seconds": seconds});
            if let Some(i) = sm.get_one::<String>("iface") {
                body["iface"] = json!(i);
            }
            call(&c.api, "POST", "/api/net/capture", Some(&body), seconds as f64 + 20.0)?
        }
        _ => {
            let mut body = Map::new();
            for k in ["iface", "cidr", "from_cidr"] {
                if let Ok(Some(v)) = sm.try_get_one::<String>(k) {
                    body.insert(k.into(), json!(v));
                }
            }
            if let Ok(Some(v)) = sm.try_get_one::<i64>("port") {
                body.insert("port".into(), json!(v));
            }
            body.insert("confirm".into(), json!(sm.get_flag("confirm")));
            call(&c.api, "POST", &format!("/api/net/{act}"), Some(&Value::Object(body)), 30.0)?
        }
    };
    emit(c.io, c.json, &r, print_net_result);
    Ok(())
}

fn cmd_serve(io: &mut Io, m: &ArgMatches) -> R<i32> {
    crate::log::init(if m.get_flag("verbose") { crate::log::Level::Debug } else { crate::log::Level::Info });
    let (path, note) = resolve_config(m.get_one::<String>("config").map(String::as_str));
    if !note.is_empty() {
        crate::log::warning("scapegoat", &note);
    }
    let mut cfg = crate::config::load(&path, m.get_one::<String>("profile").map(String::as_str))
        .map_err(|e| CliError(format!("config problem: {e}")))?;
    if !cfg.profile.is_empty() {
        crate::log::info(
            "scapegoat",
            &format!("config {} over profile {} ({})", cfg.path, cfg.profile, cfg.get_str("profile_path").unwrap_or("None".into())),
        );
    }
    if let Some(b) = m.get_one::<String>("bind") {
        cfg.bind = b.clone();
        cfg.raw.insert("bind".into(), json!(b));
    }
    let _ = io;
    crate::service::run_forever(cfg, m.get_one::<String>("session").map(String::as_str)).map_err(CliError)
}

// ---------------------------------------------------------------- parser
fn common(c: Command) -> Command {
    c.arg(
        Arg::new("api")
            .long("api")
            .value_name("URL")
            .global(true)
            .help(format!("address of the scapegoat service (default {}; env SCAPEGOAT_API)", default_api())),
    )
    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue).global(true).help("print raw JSON instead of text"))
}

fn session_arg() -> Arg {
    Arg::new("session").required(true).help("session name (e.g. sensor)")
}

pub fn build_parser() -> Command {
    let mut p = Command::new("scapegoat")
        .about("scapegoat plays the C2 side of a sensor link so the sensor starts sending data. Run `scapegoat serve` as the service; the other commands talk to the running service.")
        .after_help("Examples:\n  scapegoat status\n  scapegoat events sensor -n 20\n  scapegoat action sensor ask_reply\n  scapegoat net ping 192.0.2.81")
        .disable_version_flag(true)
        .subcommand_value_name("COMMAND");
    p = common(p);
    p = p.subcommand(
        Command::new("serve")
            .about("run the scapegoat service (normally started by systemd)")
            .long_about("Run the service: open one UDP socket per session, send keepalives, and serve the API and web page.")
            .arg(
                Arg::new("config")
                    .long("config")
                    .value_name("PATH")
                    .help(format!("config file (default {DEFAULT_CONFIG}; env SCAPEGOAT_CONFIG)")),
            )
            .arg(
                Arg::new("profile")
                    .long("profile")
                    .value_name("NAME")
                    .help("profile to layer the config over (overrides `profile` in the file); list them with `scapegoat profiles`"),
            )
            .arg(
                Arg::new("session")
                    .long("session")
                    .value_name("ID")
                    .help("run only this one session from the config (one sensor per process)"),
            )
            .arg(Arg::new("bind").long("bind").value_name("IP:PORT").help("override the API address from the config"))
            .arg(Arg::new("verbose").short('v').long("verbose").action(ArgAction::SetTrue).help("debug logging")),
    );
    p = p.subcommand(
        Command::new("status")
            .about("show every session's link state")
            .long_about("Show each session: state, peer, time since last receive/send, datagram counts. Give a session name for detail and per-message counts.")
            .arg(Arg::new("session").help("session name for detail (e.g. sensor)")),
    );
    p = p.subcommand(
        Command::new("events")
            .about("show recent events")
            .long_about("Show recent events: state changes, actions with who ran them, errors.")
            .arg(Arg::new("session").help("session name (default: all sessions)"))
            .arg(
                Arg::new("n")
                    .short('n')
                    .value_parser(clap::value_parser!(i64))
                    .allow_negative_numbers(true)
                    .default_value("50")
                    .help("how many events (default 50)"),
            ),
    );
    p = p.subcommand(
        Command::new("actions")
            .about("list the manual triggers of a session")
            .long_about("List the manual triggers a session offers and whether each is allowed.")
            .arg(session_arg()),
    );
    p = p.subcommand(
        Command::new("action")
            .about("send a manual trigger")
            .long_about("Send one manual trigger to the sensor. Triggers that command the sensor (actions the protocol marks dangerous) are locked: without --arm the command only says what it would do; with --arm it asks you to type the device ID (or give it with --confirm ID). One command per arm.")
            .after_help("Examples:\n  scapegoat action sensor ask_reply\n  scapegoat action sensor <dangerous-action> --arm --confirm <id>")
            .arg(session_arg())
            .arg(Arg::new("name").required(true).help("trigger name; list them with `scapegoat actions <session>`"))
            .arg(Arg::new("values").num_args(0..).help("the trigger's values, in order or name=value (e.g. <action> <value> <value>)"))
            .arg(Arg::new("arm").long("arm").action(ArgAction::SetTrue).help("unlock this one dangerous trigger and send it"))
            .arg(Arg::new("confirm").long("confirm").value_name("DEVICE_ID").help("the device ID, for scripts (otherwise you are asked to type it)")),
    );
    for (name, text) in [
        ("enable", "start a session (opens its socket, sends keepalives)"),
        ("disable", "stop a session (closes its socket)"),
        ("reset", "zero a session's counters and restart the handshake"),
    ] {
        p = p.subcommand(Command::new(name).about(text).long_about(format!("{}.", capitalize_first(text))).arg(session_arg()));
    }
    p = p.subcommand(
        Command::new("watch")
            .about("watch every message on a session live")
            .long_about("Follow every message the session sends, receives and forwards, one line each. Ctrl-C stops. With --wire, capture the session's UDP port from the network instead (also shows traffic scapegoat is not part of, e.g. a real scapegoat talking to the sensor; needs root).")
            .after_help("Arrows: -> sent by scapegoat, <- received, => forwarded copy, ~~ seen on the wire.  !! marks a message that failed checks.\nExamples:\n  scapegoat watch sensor\n  scapegoat watch sensor --filter Keep --fields\n  scapegoat watch sensor --wire")
            .arg(session_arg())
            .arg(Arg::new("fields").long("fields").action(ArgAction::SetTrue).help("print every decoded field"))
            .arg(Arg::new("hex").long("hex").action(ArgAction::SetTrue).help("print the raw bytes in hex"))
            .arg(Arg::new("filter").long("filter").value_name("NAME").help("only messages whose name contains NAME"))
            .arg(Arg::new("wire").long("wire").action(ArgAction::SetTrue).help("capture from the network (tcpdump) instead of the session log"))
            .arg(Arg::new("seconds").long("seconds").value_parser(clap::value_parser!(f64)).default_value("5").help("with --wire: length of each capture round (default 5)"))
            .arg(Arg::new("last").long("last").value_parser(clap::value_parser!(i64)).allow_negative_numbers(true).default_value("20").help("messages already in the log to show first (default 20)"))
            .arg(Arg::new("once").long("once").action(ArgAction::SetTrue).hide(true)),
    );
    p = p.subcommand(
        Command::new("lock")
            .about("lock a session onto one sensor address")
            .long_about("Stop probing the other peer candidates and talk only to this address. `scapegoat reset <session>` undoes it.")
            .arg(session_arg())
            .arg(Arg::new("peer").required(true).help("sensor address IP:PORT, e.g. 192.0.2.74:47000")),
    );
    p = p.subcommand(
        Command::new("profiles")
            .about("list the config profiles you can use")
            .long_about("List config profiles (installed in /etc/scapegoat/profiles and shipped with scapegoat) with what each is for.")
            .arg(
                Arg::new("profiles_dir")
                    .long("profiles-dir")
                    .alias("profiles_dir")
                    .value_name("DIR")
                    .help("look here first (default /etc/scapegoat/profiles)"),
            ),
    );
    let mut net = Command::new("net")
        .about("network checks and fixes on this node")
        .long_about("Show the node's network (interfaces, neighbors, routes, peer reachability, listeners, firewall), ping, capture packets, or change the network. Changes need allow_net_control = true in the config AND --confirm.")
        .subcommand_value_name("ACTION")
        .subcommand(Command::new("show").about("show the network snapshot (default)"))
        .subcommand(
            Command::new("ping")
                .about("ping an address from this node")
                .arg(Arg::new("ip").required(true).help("address to ping, e.g. the sensor address"))
                .arg(Arg::new("count").long("count").value_parser(clap::value_parser!(i64)).default_value("3").help("number of pings (default 3)")),
        )
        .subcommand(
            Command::new("capture")
                .about("capture UDP packets on a port for a few seconds")
                .arg(Arg::new("seconds").long("seconds").value_parser(clap::value_parser!(i64)).default_value("10").help("how long (default 10)"))
                .arg(Arg::new("port").long("port").value_parser(clap::value_parser!(i64)).default_value("47000").help("UDP port (default 47000)"))
                .arg(Arg::new("iface").long("iface").help("interface (default: all)")),
        );
    let ctl: [(&str, &str, &[&str]); 6] = [
        ("addr_add", "add an IP address to an interface", &["iface", "cidr"]),
        ("addr_del", "remove an IP address from an interface", &["iface", "cidr"]),
        ("link_up", "bring an interface up", &["iface"]),
        ("link_down", "take an interface down", &["iface"]),
        ("neigh_flush", "flush the neighbor (ARP) table of an interface", &["iface"]),
        ("fw_allow", "allow UDP from a network to a port in the firewall", &["iface", "from_cidr", "port"]),
    ];
    for (act, text, fields) in ctl {
        let mut c = Command::new(act)
            .about(format!("{text} (needs --confirm)"))
            .long_about(format!("{}. Needs allow_net_control = true in the config and --confirm.", capitalize_first(text)));
        for f in fields {
            let a = match *f {
                "port" => Arg::new("port").long("port").required(true).value_parser(clap::value_parser!(i64)).help("UDP port, e.g. 47000"),
                "iface" => Arg::new("iface").long("iface").required(true).help("interface name, e.g. eth0"),
                "cidr" => Arg::new("cidr").long("cidr").required(true).help("address with prefix, e.g. 192.0.2.10/24"),
                _ => Arg::new("from_cidr").long("from_cidr").alias("from-cidr").required(true).help("source network, e.g. 192.0.2.0/24"),
            };
            c = c.arg(a);
        }
        c = c.arg(Arg::new("confirm").long("confirm").action(ArgAction::SetTrue).help("confirm the change"));
        net = net.subcommand(c);
    }
    p = p.subcommand(net);
    p = p.subcommand(
        Command::new("check-config")
            .about("check a config file the way serve loads it (for installers)")
            .hide(true)
            .arg(Arg::new("path").required(true).help("config file"))
            .arg(Arg::new("profile").long("profile").value_name("NAME").help("profile to layer the config over")),
    );
    p = p.subcommand(
        Command::new("sim")
            .about("run a sensor simulator (for tests and demos)")
            .long_about("Run a simulator: `toy` ships with scapegoat; protocol plugins add their own. `scapegoat sim toy --help` shows its options.")
            .arg(Arg::new("which").required(true).help("which simulator, e.g. toy")),
    );
    p
}

fn capitalize_first(t: &str) -> String {
    let mut c = t.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Run a simulator by name with the rest of the command line.
pub fn run_sim(io: &mut Io, which: &str, rest: Vec<String>) -> i32 {
    let reg = crate::protocol::Registry::current();
    let sims = reg.simulators();
    match sims.iter().find(|(s, _, _)| s == which) {
        Some((_, _, main)) => main(rest),
        None => {
            let mut have: Vec<String> = sims.iter().map(|(s, _, _)| s.clone()).collect();
            have.sort();
            let have = if have.is_empty() { "none".to_string() } else { have.join(", ") };
            let _ = writeln!(io.err, "scapegoat: no simulator {} installed (have: {have})", pyfmt::str_repr(which));
            1
        }
    }
}

/// The whole command line. Returns the exit code.
pub fn main_io(argv: Vec<String>, io: &mut Io) -> i32 {
    if argv.first().map(String::as_str) == Some("--version") {
        io.print(&format!("scapegoat {}", crate::VERSION));
        return 0;
    }
    // `scapegoat sim <name> ...`: everything after the simulator name goes to it untouched.
    if argv.len() >= 2 && argv[0] == "sim" && !argv[1].starts_with('-') {
        return run_sim(io, &argv[1], argv[2..].to_vec());
    }
    let mut parser = build_parser();
    let m = match parser.clone().try_get_matches_from(std::iter::once("scapegoat".to_string()).chain(argv)) {
        Ok(m) => m,
        Err(e) => {
            let text = e.render().to_string();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    io.write(&text);
                    0
                }
                _ => {
                    let _ = write!(io.err, "{text}");
                    2
                }
            };
        }
    };
    let Some((cmd, sm)) = m.subcommand() else {
        io.write(&parser.render_help().to_string());
        return 2;
    };
    let api = sm.get_one::<String>("api").or(m.get_one::<String>("api")).cloned().unwrap_or_else(default_api);
    let json_out = sm.get_flag("json") || m.get_flag("json");
    let r: R<i32> = match cmd {
        "serve" => cmd_serve(io, sm),
        "check-config" => crate::config::load(sm.get_one::<String>("path").unwrap(), sm.get_one::<String>("profile").map(String::as_str))
            .map(|_| 0)
            .map_err(|e| CliError(format!("config problem: {e}"))),
        "sim" => Ok(run_sim(io, sm.get_one::<String>("which").unwrap(), vec![])),
        _ => {
            let mut c = Ctx { io, api, json: json_out };
            match cmd {
                "profiles" => {
                    cmd_profiles(&mut c, sm);
                    Ok(0)
                }
                "status" => cmd_status(&mut c, sm).map(|_| 0),
                "events" => cmd_events(&mut c, sm).map(|_| 0),
                "actions" => cmd_actions(&mut c, sm).map(|_| 0),
                "action" => cmd_action(&mut c, sm).map(|_| 0),
                "enable" | "disable" | "reset" => cmd_lifecycle(&mut c, cmd, sm).map(|_| 0),
                "net" => cmd_net(&mut c, sm).map(|_| 0),
                "lock" => cmd_lock(&mut c, sm).map(|_| 0),
                "watch" => cmd_watch(&mut c, sm).map(|_| 0),
                _ => Ok(2),
            }
        }
    };
    match r {
        Ok(_) if cmd == "watch" && crate::signals::stopped() => 130,
        Ok(code) => code,
        Err(CliError(msg)) => {
            let _ = writeln!(io.err, "scapegoat: {msg}");
            1
        }
    }
}

/// The command line on the process's stdin, stdout and stderr.
pub fn main(argv: Vec<String>) -> i32 {
    crate::signals::install();
    let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut io = Io { out: &mut out, err: &mut err, input: &mut input };
    main_io(argv, &mut io)
}
