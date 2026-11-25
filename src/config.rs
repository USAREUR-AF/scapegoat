// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Load the scapegoat config file: TOML, or a JSON file with the same structure.
//!
//! Every key, default and refusal message is the Python version's, so a deployed node's
//! config keeps working unchanged. `Config::raw` is the parsed file with defaults filled
//! in, for code that treats the config as a table.

use crate::protocol::Registry;
use crate::pyfmt;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub const DEFAULT_PROFILES_DIR: &str = "/etc/scapegoat/profiles";
/// Where the profiles built into the binary are said to be (they have no file).
pub const BUILTIN_PROFILES: &str = "<built into scapegoat>";
pub const SYSTEM_PLUGIN_DIRS: [&str; 2] = ["/etc/scapegoat/plugins", "/opt/scapegoat/plugins"];
pub const OUTPUT_FORMATS: [&str; 3] = ["asterix-cat062", "cot-xml", "sapient"];

static EXTRA_PLUGIN_DIRS: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// The config file is missing or wrong. The message says what to fix.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

type R<T> = Result<T, ConfigError>;

fn err<T>(s: impl Into<String>) -> R<T> {
    Err(ConfigError(s.into()))
}

pub type Addr = (String, u16);

pub fn fmt_addr(a: &Addr) -> String {
    format!("{}:{}", a.0, a.1)
}

/// Python truthiness of a JSON value.
pub fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

/// `str(v)` for a value read from the file.
fn s(v: &Value) -> String {
    pyfmt::str(v)
}

/// `str(data.get(key) or "")`.
fn s_or_empty(v: Option<&Value>) -> String {
    if truthy(v) {
        s(v.unwrap())
    } else {
        String::new()
    }
}

/// '192.0.2.5:47000' -> ("192.0.2.5", 47000).
pub fn parse_addr(text: &Value, what: &str) -> R<Addr> {
    let t = match text {
        Value::String(t) if t.contains(':') => t,
        other => return err(format!("{what}: expected 'IP:PORT', got {}", pyfmt::repr(other))),
    };
    let (host, port) = t.rsplit_once(':').unwrap();
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let p: i64 = match py_int(port) {
        Some(p) => p,
        None => return err(format!("{what}: port must be a number, got {}", pyfmt::str_repr(port))),
    };
    if !(0..=65535).contains(&p) {
        return err(format!("{what}: port {p} out of range"));
    }
    Ok((host.to_string(), p as u16))
}

pub fn parse_addr_str(text: &str, what: &str) -> R<Addr> {
    parse_addr(&Value::String(text.into()), what)
}

/// Python `int(text)`: surrounding spaces, a sign and `_` between digits are allowed.
pub fn py_int(text: &str) -> Option<i64> {
    let t = text.trim();
    let (neg, digits) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    if !clean.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: i64 = clean.parse().ok()?;
    Some(if neg { -v } else { v })
}

#[derive(Clone, Debug, Default)]
pub struct SessionConfig {
    pub id: String,
    pub protocol: String,
    pub enabled: bool,
    /// "" = 0.0.0.0 on the protocol's default port.
    pub local: String,
    pub peer: String,
    pub peer_candidates: Vec<String>,
    pub forward: Vec<String>,
    pub allow_transmit_control: bool,
    pub protocol_settings: Map<String, Value>,
    /// Copied from `[features] transmit_control`. False hides transmit actions everywhere.
    pub transmit_feature: bool,
    /// A plugin's address check may honour this (a peer on a private internal network).
    pub direct_internal_network: bool,
    /// "message": forward each message; "datagram": forward each datagram unchanged.
    pub forward_mode: String,
}

impl SessionConfig {
    pub fn local_addr(&self) -> R<Addr> {
        if self.local.is_empty() {
            return Ok(("0.0.0.0".into(), 0));
        }
        parse_addr_str(&self.local, &format!("sessions.{}.local", self.id))
    }

    /// `peer` first (if set), then `peer_candidates`, duplicates dropped.
    pub fn candidate_addrs(&self) -> R<Vec<Addr>> {
        let mut out: Vec<Addr> = vec![];
        let mut texts = vec![];
        if !self.peer.is_empty() {
            texts.push(self.peer.clone());
        }
        texts.extend(self.peer_candidates.iter().cloned());
        for t in texts {
            let a = parse_addr_str(&t, &format!("sessions.{}.peer", self.id))?;
            if !out.contains(&a) {
                out.push(a);
            }
        }
        Ok(out)
    }

    pub fn peer_addr(&self) -> R<Addr> {
        Ok(self.candidate_addrs()?.remove(0))
    }

    pub fn forward_addrs(&self) -> R<Vec<Addr>> {
        self.forward.iter().map(|f| parse_addr_str(f, &format!("sessions.{}.forward", self.id))).collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub bind: String,
    pub allow_net_control: bool,
    pub node_name: String,
    pub island_rest: String,
    pub expected_local_address: String,
    /// "routed" | "same-lan" | "" (inferred by `scapegoat net`).
    pub topology: String,
    /// Free text shown first on every page.
    pub node_role: String,
    pub features: Map<String, Value>,
    /// C2 outputs: name -> checked spec (see outputs.rs).
    pub outputs: Map<String, Value>,
    pub transformers_path: String,
    pub profile: String,
    pub sessions: Vec<SessionConfig>,
    pub path: String,
    pub raw: Map<String, Value>,
}

impl Config {
    pub fn bind_addr(&self) -> R<Addr> {
        parse_addr_str(&self.bind, "bind")
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.raw.get(key)
    }

    pub fn get_str(&self, key: &str) -> Option<String> {
        self.raw.get(key).filter(|v| truthy(Some(v))).map(pyfmt::str)
    }

    pub fn session(&self, id: &str) -> Option<&SessionConfig> {
        self.sessions.iter().find(|s| s.id == id)
    }
}

fn boolean(v: Option<&Value>, default: bool, what: &str) -> R<bool> {
    match v {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(other) => err(format!("{what}: expected true or false, got {}", pyfmt::repr(other))),
    }
}

fn is_int(v: &Value) -> bool {
    matches!(v, Value::Number(n) if !n.is_f64())
}

/// `[outputs.<name>]` tables -> checked output specs.
fn outputs(raw: &Value, island_rest: &str) -> R<Map<String, Value>> {
    let m = match raw {
        Value::Object(m) => m,
        _ => return err("[outputs] must be tables, e.g. [outputs.cat062]"),
    };
    let mut out = Map::new();
    for (name, o) in m {
        let w = format!("outputs.{name}");
        let o = match o {
            Value::Object(o) => o,
            _ => return err(format!("[{w}] must be a table")),
        };
        let fmt = o.get("format").map(s).unwrap_or_default();
        if !OUTPUT_FORMATS.contains(&fmt.as_str()) {
            return err(format!("{w}.format must be one of {}", OUTPUT_FORMATS.join(", ")));
        }
        let to = match o.get("to") {
            None => vec![],
            Some(Value::Array(a)) => a.clone(),
            Some(_) => vec![Value::Null],
        };
        if !matches!(o.get("to"), None | Some(Value::Array(_))) || to.is_empty() {
            return err(format!("{w}.to: list the destinations, e.g. [\"udp://239.255.62.1:8600\", \"zenoh:site/sensor/cat062\"]"));
        }
        let mut dests = vec![];
        for d in &to {
            match crate::destinations::parse_destination(&s(d)) {
                Ok(x) => dests.push(x),
                Err(e) => return err(format!("{w}: {e}")),
            }
        }
        let enabled = boolean(o.get("enabled"), true, &format!("{w}.enabled"))?;
        if enabled && dests.iter().any(|d| d.is_zenoh()) && island_rest.is_empty() {
            return err(format!("{w}: a zenoh: destination needs island_rest (the Zenoh REST address, e.g. http://127.0.0.1:8000)"));
        }
        let sessions = match o.get("sessions") {
            None => vec![],
            Some(Value::Array(a)) => a.iter().map(|x| json!(s(x))).collect(),
            Some(_) => return err(format!("{w}.sessions must be a list of session names")),
        };
        let mut context = Map::new();
        match fmt.as_str() {
            "asterix-cat062" => {
                for k in ["sac", "sic"] {
                    let v = o.get(k);
                    let good = matches!(v, Some(x) if is_int(x) && (0..=255).contains(&x.as_i64().unwrap_or(-1)));
                    if !good {
                        return err(format!(
                            "{w}.{k} is required for CAT062: 0-255 (System Area Code / System Identification Code of this source)"
                        ));
                    }
                    context.insert(format!("cat062.{k}"), v.unwrap().clone());
                }
            }
            "cot-xml" => {
                context.insert("how".into(), json!(o.get("how").map(s).unwrap_or("m-g".into())));
            }
            _ => {
                if !truthy(o.get("node_id")) {
                    return err(format!("{w}.node_id is required for SAPIENT (a UUID)"));
                }
                context.insert("sapient.node_id".into(), json!(s(&o["node_id"])));
            }
        }
        let stale = o.get("stale_s").cloned().unwrap_or(json!(30));
        let stale_f = match &stale {
            Value::Number(n) => n.as_f64().unwrap_or(0.0),
            _ => -1.0,
        };
        if stale_f <= 0.0 {
            return err(format!("{w}.stale_s must be a positive number of seconds"));
        }
        let ttl = match o.get("multicast_ttl") {
            None => 1,
            Some(v) => match v {
                Value::Number(n) => n.as_f64().map(|f| f.trunc() as i64).unwrap_or(1),
                Value::String(t) => {
                    py_int(t).ok_or_else(|| ConfigError(format!("invalid literal for int() with base 10: {}", pyfmt::str_repr(t))))?
                }
                Value::Bool(b) => *b as i64,
                other => return err(format!("int() argument must be a string or a number, not {}", pyfmt::repr(other))),
            },
        };
        out.insert(
            name.clone(),
            json!({
                "format": fmt, "enabled": enabled,
                "to": dests.iter().map(|d| d.text()).collect::<Vec<_>>(),
                "sessions": sessions, "multicast_ttl": ttl, "context": context,
                "uid_prefix": o.get("uid_prefix").cloned().unwrap_or(Value::Null),
                "stale_s": stale_f,
            }),
        );
    }
    Ok(out)
}

/// A copy of `table` with each old key renamed to its new name. Both set is an error.
pub fn apply_aliases(table: &Map<String, Value>, aliases: &[(String, String)], where_: &str) -> R<Map<String, Value>> {
    let mut out = table.clone();
    for (old, new) in aliases {
        if let Some(v) = out.get(old).cloned() {
            if out.contains_key(new) {
                return err(format!("{where_}: set {new} or its old name {old}, not both"));
            }
            // keep the key's place in the table
            let pos = out.keys().position(|k| k == old).unwrap();
            let mut renamed = Map::new();
            for (i, (k, x)) in out.into_iter().enumerate() {
                if i == pos {
                    renamed.insert(new.clone(), v.clone());
                } else {
                    renamed.insert(k, x);
                }
            }
            out = renamed;
        }
    }
    Ok(out)
}

/// Directories from the site config's `plugin_path`.
pub fn set_extra_plugin_dirs(dirs: Vec<String>) {
    *EXTRA_PLUGIN_DIRS.write().unwrap() = dirs;
}

/// SCAPEGOAT_PLUGIN_PATH, then `plugin_path`, then the system directories, then
/// `plugins/` in a source checkout. Read for the profiles a plugin ships.
pub fn plugin_dirs() -> Vec<String> {
    let mut dirs: Vec<String> =
        std::env::var("SCAPEGOAT_PLUGIN_PATH").unwrap_or_default().split(':').filter(|d| !d.is_empty()).map(String::from).collect();
    dirs.extend(EXTRA_PLUGIN_DIRS.read().unwrap().iter().cloned());
    dirs.extend(SYSTEM_PLUGIN_DIRS.iter().map(|s| s.to_string()));
    dirs.push(checkout_dir().join("plugins").to_string_lossy().to_string());
    let mut seen = vec![];
    for d in dirs {
        if !seen.contains(&d) {
            seen.push(d);
        }
    }
    seen
}

/// The source checkout the binary runs from (`target/<profile>/scapegoat` or `bin/<arch>/`),
/// or the binary's directory.
pub fn checkout_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let mut p = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    for _ in 0..4 {
        if p.join("Cargo.toml").is_file() {
            return p;
        }
        if !p.pop() {
            break;
        }
    }
    exe.parent().map(Path::to_path_buf).unwrap_or_default()
}

pub fn from_dict(data: &Value, path: &str) -> R<Config> {
    let d = match data {
        Value::Object(m) => m,
        _ => return err("config must be a table of settings"),
    };
    let mut cfg = Config {
        bind: d.get("bind").map(s).unwrap_or("127.0.0.1:8730".into()),
        allow_net_control: boolean(d.get("allow_net_control"), false, "allow_net_control")?,
        node_name: d.get("node_name").map(s).unwrap_or("scapegoat".into()),
        island_rest: s_or_empty(d.get("island_rest")),
        expected_local_address: s_or_empty(d.get("expected_local_address")),
        profile: s_or_empty(d.get("profile")),
        path: path.into(),
        ..Default::default()
    };
    cfg.bind_addr()?;
    let topo = s_or_empty(d.get("topology"));
    if !["", "routed", "same-lan"].contains(&topo.as_str()) {
        return err(format!("topology must be \"routed\" or \"same-lan\" (or left out), got {}", pyfmt::str_repr(&topo)));
    }
    cfg.topology = topo;
    cfg.node_role = s_or_empty(d.get("node_role")).trim().to_string();
    if let Some(t) = d.get("transformers").filter(|v| truthy(Some(v))) {
        match t {
            Value::Object(t) => cfg.transformers_path = s_or_empty(t.get("path")),
            _ => return err("'transformers' must be a table"),
        }
    }
    let outs = d.get("outputs").filter(|v| truthy(Some(v))).cloned().unwrap_or(json!({}));
    cfg.outputs = outputs(&outs, &cfg.island_rest)?;
    let ppath = match d.get("plugin_path").filter(|v| truthy(Some(v))) {
        None => vec![],
        Some(Value::String(p)) => vec![p.clone()],
        Some(Value::Array(a)) => a.iter().map(s).collect(),
        Some(_) => return err("plugin_path must be a list of directories, e.g. [\"/opt/scapegoat/plugins\"]"),
    };
    set_extra_plugin_dirs(ppath);
    let reg = Registry::current();
    let feats = d.get("features").filter(|v| truthy(Some(v))).cloned().unwrap_or(json!({}));
    let feats = match feats {
        Value::Object(m) => m,
        _ => return err("[features] must be a table, e.g. [features] transmit_control = false"),
    };
    let feats = apply_aliases(&feats, &reg.config_aliases("features", None), "[features]")?;
    let transmit = boolean(feats.get("transmit_control"), false, "features.transmit_control")?;
    cfg.features = json!({"transmit_control": transmit}).as_object().unwrap().clone();
    let sessions = d.get("sessions").filter(|v| truthy(Some(v))).cloned().unwrap_or(json!({}));
    let sessions = match sessions {
        Value::Object(m) => m,
        _ => return err("[sessions] must be a table, e.g. [sessions.sensor]"),
    };
    let mut raw_sessions = Map::new();
    for (sid, sv) in &sessions {
        let sm = match sv {
            Value::Object(m) => m,
            _ => return err(format!("[sessions.{sid}] must be a table")),
        };
        if !truthy(sm.get("protocol")) {
            return err(format!("sessions.{sid}.protocol is required (for example \"toy\")"));
        }
        let sm = &apply_aliases(sm, &reg.config_aliases("session", Some(&s(&sm["protocol"]))), &format!("[sessions.{sid}]"))?;
        let cands = match sm.get("peer_candidates").filter(|v| truthy(Some(v))) {
            None => vec![],
            Some(Value::Array(a)) => a.clone(),
            Some(_) => {
                return err(format!("sessions.{sid}.peer_candidates must be a list like [\"192.0.2.81:47000\", \"192.0.2.74:47000\"]"))
            }
        };
        if !truthy(sm.get("peer")) && cands.is_empty() {
            return err(format!("sessions.{sid}.peer is required: the sensor's IP:PORT (or give peer_candidates)"));
        }
        let fwd = match sm.get("forward").filter(|v| truthy(Some(v))) {
            None => vec![],
            Some(Value::Array(a)) => a.clone(),
            Some(_) => return err(format!("sessions.{sid}.forward must be a list like [\"127.0.0.1:40531\"]")),
        };
        let ps = match sm.get("protocol_settings").filter(|v| truthy(Some(v))) {
            None => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return err(format!("[sessions.{sid}.protocol_settings] must be a table")),
        };
        let sc = SessionConfig {
            id: sid.clone(),
            protocol: s(&sm["protocol"]),
            enabled: boolean(sm.get("enabled"), true, &format!("sessions.{sid}.enabled"))?,
            local: s_or_empty(sm.get("local")),
            peer: s_or_empty(sm.get("peer")),
            peer_candidates: cands.iter().map(s).collect(),
            forward: fwd.iter().map(s).collect(),
            allow_transmit_control: boolean(sm.get("allow_transmit_control"), false, &format!("sessions.{sid}.allow_transmit_control"))?,
            protocol_settings: ps,
            transmit_feature: transmit,
            direct_internal_network: boolean(sm.get("direct_internal_network"), false, &format!("sessions.{sid}.direct_internal_network"))?,
            forward_mode: sm.get("forward_mode").map(s).unwrap_or("message".into()),
        };
        if sc.forward_mode != "message" && sc.forward_mode != "datagram" {
            return err(format!("sessions.{sid}.forward_mode must be \"message\" or \"datagram\""));
        }
        sc.local_addr()?;
        sc.candidate_addrs()?;
        sc.forward_addrs()?;
        if let Some(p) = reg.get(&sc.protocol) {
            if let Some(v) = p.validate_session {
                v(&sc).map_err(ConfigError)?;
            }
        }
        raw_sessions.insert(
            sc.id.clone(),
            json!({
                "id": sc.id, "protocol": sc.protocol, "enabled": sc.enabled,
                "local": sc.local, "peer": sc.peer,
                "peer_candidates": sc.peer_candidates, "forward": sc.forward,
                "allow_transmit_control": sc.allow_transmit_control,
                "protocol_settings": sc.protocol_settings,
            }),
        );
        cfg.sessions.push(sc);
    }
    let mut raw = d.clone();
    for (k, v) in [
        ("bind", json!(cfg.bind)),
        ("allow_net_control", json!(cfg.allow_net_control)),
        ("node_name", json!(cfg.node_name)),
        ("island_rest", json!(cfg.island_rest)),
        ("expected_local_address", json!(cfg.expected_local_address)),
        ("profile", json!(cfg.profile)),
        ("features", Value::Object(cfg.features.clone())),
        ("topology", json!(cfg.topology)),
        ("node_role", json!(cfg.node_role)),
        ("outputs", Value::Object(cfg.outputs.clone())),
        ("sessions", Value::Object(raw_sessions)),
    ] {
        raw.insert(k.into(), v);
    }
    cfg.raw = raw;
    Ok(cfg)
}

fn toml_to_json(v: toml::Value) -> Value {
    match v {
        toml::Value::String(s) => Value::String(s),
        toml::Value::Integer(i) => json!(i),
        toml::Value::Float(f) => json!(f),
        toml::Value::Boolean(b) => Value::Bool(b),
        toml::Value::Datetime(d) => Value::String(d.to_string()),
        toml::Value::Array(a) => Value::Array(a.into_iter().map(toml_to_json).collect()),
        toml::Value::Table(t) => Value::Object(t.into_iter().map(|(k, v)| (k, toml_to_json(v))).collect()),
    }
}

/// Parse config text: JSON when it starts with `{`, TOML otherwise.
pub fn parse_text(text: &str, path: &str) -> R<Map<String, Value>> {
    let data = if text.trim_start().starts_with('{') {
        serde_json::from_str::<Value>(text).map_err(|e| ConfigError(format!("{path}: bad JSON: {e}")))?
    } else {
        let t: toml::Table = toml::from_str(text).map_err(|e| ConfigError(format!("{path}: bad TOML: {}", e.message())))?;
        toml_to_json(toml::Value::Table(t))
    };
    match data {
        Value::Object(m) => Ok(m),
        _ => err(format!("{path}: must be a table of settings")),
    }
}

/// Read one config or profile file (or a profile built into the binary).
pub fn read(path: &str) -> R<Map<String, Value>> {
    if let Some(text) = builtin_profile_text(path) {
        return parse_text(&text, path);
    }
    let p = Path::new(path);
    if !p.is_file() {
        return err(format!("config file not found: {path}"));
    }
    let bytes = std::fs::read(p).map_err(|e| ConfigError(format!("config file not found: {path} ({e})")))?;
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => return err(format!("{path}: bad TOML: {e}")),
    };
    parse_text(&text, path)
}

/// Tables merge key by key; any other value in `over` (lists too) replaces `base`.
pub fn deep_merge(base: &Map<String, Value>, over: &Map<String, Value>) -> Map<String, Value> {
    let mut out = base.clone();
    for (k, v) in over {
        match (v, out.get(k)) {
            (Value::Object(vo), Some(Value::Object(bo))) => {
                let merged = deep_merge(bo, vo);
                out.insert(k.clone(), Value::Object(merged));
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    out
}

fn builtin_profile_text(path: &str) -> Option<String> {
    let name = path.strip_prefix(BUILTIN_PROFILES)?.strip_prefix('/')?;
    let stem = name.strip_suffix(".toml").or_else(|| name.strip_suffix(".json"))?;
    for p in Registry::current().plugins() {
        for (n, text) in &p.profiles {
            if n == stem {
                return Some(text.clone());
            }
        }
    }
    None
}

/// Plugin profile directories found on the plugin path (`<dir>/<name>/profiles`).
fn plugin_profile_dirs() -> Vec<String> {
    let mut out = vec![];
    for d in plugin_dirs() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        let mut names: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        names.sort();
        for p in names {
            let prof = p.join("profiles");
            if prof.is_dir() {
                out.push(prof.to_string_lossy().to_string());
            }
        }
    }
    out
}

/// Site profiles dir, any dirs a site extension adds, the profiles built into the binary,
/// then profiles found beside plugins on the plugin path.
pub fn profile_dirs(profiles_dir: Option<&str>) -> Vec<String> {
    let mut dirs = vec![profiles_dir.unwrap_or(DEFAULT_PROFILES_DIR).to_string()];
    dirs.extend(crate::extension::current().profile_dirs);
    dirs.push(BUILTIN_PROFILES.to_string());
    dirs.extend(plugin_profile_dirs());
    let mut seen = vec![];
    for d in dirs {
        if !seen.contains(&d) {
            seen.push(d);
        }
    }
    seen
}

fn description(text: &str) -> String {
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            return t.trim_start_matches('#').trim().to_string();
        }
        if !t.is_empty() {
            break;
        }
    }
    String::new()
}

/// (stem, path, text) of every profile file in one directory, sorted by file name.
fn profiles_in(dir: &str) -> Vec<(String, String, String)> {
    if dir == BUILTIN_PROFILES {
        let mut out = vec![];
        for p in Registry::current().plugins() {
            for (n, text) in &p.profiles {
                out.push((n.clone(), format!("{BUILTIN_PROFILES}/{n}.toml"), text.clone()));
            }
        }
        out.sort_by(|a, b| a.1.cmp(&b.1));
        return out;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut files: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    files.sort();
    let mut out = vec![];
    for f in files {
        let ext = f.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "toml" && ext != "json" {
            continue;
        }
        let stem = f.file_stem().and_then(|e| e.to_str()).unwrap_or("").to_string();
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        out.push((stem, f.to_string_lossy().to_string(), text));
    }
    out
}

/// Profiles found, first directory wins on a name clash, sorted by name.
pub fn list_profiles(profiles_dir: Option<&str>) -> Vec<Value> {
    let mut seen: Vec<(String, Value)> = vec![];
    for d in profile_dirs(profiles_dir) {
        for (stem, path, text) in profiles_in(&d) {
            if !seen.iter().any(|(s, _)| *s == stem) {
                seen.push((stem.clone(), json!({"name": stem, "description": description(&text), "path": path})));
            }
        }
    }
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    seen.into_iter().map(|(_, v)| v).collect()
}

fn profile_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty() && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c))
}

pub fn find_profile(name: &str, profiles_dir: Option<&str>) -> R<String> {
    if !profile_name_ok(name) {
        return err(format!("bad profile name {}: use letters, digits, - _ .", pyfmt::str_repr(name)));
    }
    for d in profile_dirs(profiles_dir) {
        for ext in ["toml", "json"] {
            if d == BUILTIN_PROFILES {
                if ext == "toml" && profiles_in(&d).iter().any(|(s, _, _)| s == name) {
                    return Ok(format!("{BUILTIN_PROFILES}/{name}.toml"));
                }
                continue;
            }
            let f = Path::new(&d).join(format!("{name}.{ext}"));
            if f.is_file() {
                return Ok(f.to_string_lossy().to_string());
            }
        }
    }
    let have: Vec<String> = list_profiles(profiles_dir).iter().map(|p| p["name"].as_str().unwrap_or("").to_string()).collect();
    let have = if have.is_empty() { "none".to_string() } else { have.join(", ") };
    err(format!(
        "profile {} not found in {}. Available: {have}. List them with: scapegoat profiles",
        pyfmt::str_repr(name),
        profile_dirs(profiles_dir).join(", ")
    ))
}

/// Load the site config. If it names a profile (or `profile` is given), the profile file
/// supplies defaults and the site file overrides them.
pub fn load(path: &str, profile: Option<&str>) -> R<Config> {
    let site = read(path)?;
    let name = match profile.filter(|p| !p.is_empty()) {
        Some(p) => p.to_string(),
        None => s_or_empty(site.get("profile")),
    };
    let data = if !name.is_empty() {
        let pdir = site.get("profiles_dir").filter(|v| truthy(Some(v))).map(s);
        let pfile = find_profile(&name, pdir.as_deref())?;
        let mut merged = deep_merge(&read(&pfile)?, &site);
        merged.insert("profile".into(), json!(name));
        merged.insert("profile_path".into(), json!(pfile));
        merged
    } else {
        site
    };
    from_dict(&Value::Object(data), path)
}
