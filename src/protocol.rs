// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The Protocol trait, the data types a protocol returns, and the protocol registry.
//!
//! A protocol builds and reads bytes; the core owns sockets, timers and state. `toy` is
//! registered by the `scapegoat` binary. Every other protocol is a crate that depends on this
//! one, registers itself with [`Registry::register`] and builds its own node binary
//! (`docs/plugins.md`, ADR 0002).

use crate::pyfmt;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// One received message, as the protocol understood it.
#[derive(Clone, Debug, Default)]
pub struct Decoded {
    pub name: String,
    /// Decoded fields, in the protocol's order; shown by `watch` and the page.
    pub fields: Map<String, Value>,
    pub ok: bool,
    pub problems: Vec<String>,
    pub is_keepalive: bool,
    pub peer_tx_counter: Option<i64>,
    /// Raw numbers of fields whose `fields` entry is a label (optional).
    pub values: Map<String, Value>,
    /// The bytes the message was decoded from, for protocols that need them later.
    pub raw: Vec<u8>,
    /// Notes the protocol's `soften_problems` turned problems into (set by the core).
    pub notes: Vec<String>,
}

impl Decoded {
    pub fn new(
        name: &str,
        fields: Map<String, Value>,
        ok: bool,
        problems: Vec<String>,
        is_keepalive: bool,
        peer_tx_counter: Option<i64>,
    ) -> Self {
        Decoded { name: name.into(), fields, ok, problems, is_keepalive, peer_tx_counter, ..Default::default() }
    }

    pub fn problem(text: impl Into<String>) -> Self {
        Decoded { name: "unknown".into(), problems: vec![text.into()], ..Default::default() }
    }
}

/// A manual trigger offered to the CLI and the web page.
#[derive(Clone, Debug, Default)]
pub struct ActionSpec {
    pub name: String,
    pub label: String,
    pub dangerous: bool,
    pub description: String,
    /// Plain words naming what firing it does to the sensor; may use {device_id} and {param}.
    pub effect: String,
    /// Arguments: (name, help, default or None = required).
    pub params: Vec<(String, String, Option<Value>)>,
}

impl ActionSpec {
    pub fn new(name: &str, label: &str, dangerous: bool, description: &str) -> Self {
        ActionSpec { name: name.into(), label: label.into(), dangerous, description: description.into(), ..Default::default() }
    }
}

/// Per-candidate link facts. Owned by the core, read by the protocol.
///
/// `tx_counter`: the transmit counter of the last message we sent (0 = none yet).
/// `rx_counter`: the transmit counter of the last keepalive received from the peer.
/// The protocol calls `next_tx()` once for every message it builds that carries a transmit
/// counter. The core never advances `tx_counter` itself.
#[derive(Clone, Debug, Default)]
pub struct LinkState {
    pub tx_counter: i64,
    pub rx_counter: i64,
    pub device_id: i64,
    pub settings: Map<String, Value>,
}

impl LinkState {
    /// Advance the transmit counter (1..65535, then wraps to 1) and return it.
    pub fn next_tx(&mut self) -> i64 {
        self.tx_counter = if 0 < self.tx_counter && self.tx_counter < 65535 { self.tx_counter + 1 } else { 1 };
        self.tx_counter
    }
}

/// What `split` returns: the messages in one datagram, trailing padding bytes, and a problem.
#[derive(Clone, Debug, Default)]
pub struct Split {
    pub parts: Vec<Vec<u8>>,
    pub padding: usize,
    pub problem: String,
}

/// A normalized track for the C2 outputs (`outputs.rs`): `track_id`, `source_id`, `time`,
/// `lat`, `lon`, optional `hae`, `vel_east`/`vel_north`/`vel_up`, `confirmed`, `coasting`,
/// `final`, `simulated`, `classification`, `generation`.
pub type Track = Map<String, Value>;

/// The result of a hook that may fail; the error text is shown as an event.
pub type HookResult<T> = Result<T, String>;

/// Every protocol implements this. The defaults mean "nothing protocol-specific".
pub trait Protocol: Send {
    fn name(&self) -> &str;
    fn default_port(&self) -> u16 {
        0
    }
    fn keepalive_interval_s(&self) -> f64 {
        30.0
    }

    /// Bytes of one keepalive. Call `link.next_tx()` once for its sequence number.
    fn keepalive(&mut self, link: &mut LinkState, action: i64) -> HookResult<Vec<u8>>;
    /// Never fails on bad input: a problem goes in `Decoded::problems`.
    fn decode(&mut self, datagram: &[u8]) -> Decoded;
    /// Replies to send now, for example an answer to a keepalive request.
    fn on_receive(&mut self, _link: &mut LinkState, _msg: &Decoded) -> HookResult<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    /// Manual triggers, in the order the CLI and the page list them.
    fn actions(&self) -> Vec<ActionSpec> {
        vec![]
    }
    /// One or more datagrams to send in order.
    fn build_action(&mut self, _link: &mut LinkState, name: &str, _args: &Map<String, Value>) -> HookResult<Vec<Vec<u8>>> {
        Err(format!("unknown action {}", pyfmt::str_repr(name)))
    }
    /// The messages in one datagram. `None` (the default): the datagram is one message.
    fn split(&mut self, _datagram: &[u8]) -> Option<HookResult<Split>> {
        None
    }
    /// One short line of the fields that matter, for `watch` and the traffic page.
    fn summarize(&self, msg: &Decoded) -> HookResult<String> {
        Ok(default_summary(msg))
    }
    /// Turn tolerable problems in `msg` into notes (returns the notes; edits `msg`).
    fn soften_problems(&self, _part: &[u8], _msg: &mut Decoded) -> Vec<String> {
        vec![]
    }
    /// Messages due now (for example timing every 60 s), once a peer is locked.
    fn periodic(&mut self, _link: &mut LinkState, _now: f64) -> HookResult<Vec<Vec<u8>>> {
        Ok(vec![])
    }
    /// "This received message must be answered": what is owed, or None.
    fn owes(&self, _msg: &Decoded) -> Option<String> {
        None
    }
    /// Protocol facts for the session status (`None`: the protocol has none).
    fn status(&mut self) -> Option<HookResult<Value>> {
        None
    }
    /// Lines to add to the session's event log.
    fn drain_events(&mut self) -> Vec<String> {
        vec![]
    }
    /// Normalized tracks for the C2 outputs. `None`: the protocol yields no tracks.
    fn tracks(&mut self, _msg: &Decoded) -> Option<HookResult<Vec<Track>>> {
        None
    }

    /// Keepalive field in which the peer asks for something, and code -> the action.
    fn peer_request_field(&self) -> Option<&str> {
        None
    }
    fn peer_request_actions(&self) -> BTreeMap<i64, String> {
        BTreeMap::new()
    }
    /// Keepalive fields that carry the peer's own status.
    fn peer_status_fields(&self) -> Vec<String> {
        vec![]
    }
    /// Actions gated by `[features] transmit_control` as well as by `dangerous`.
    fn transmit_actions(&self) -> Vec<String> {
        vec![]
    }
    /// (field, value) a simulator puts in its keepalives, so status says SIMULATOR.
    fn sim_marker(&self) -> Option<(String, Value)> {
        None
    }
    /// What the CLI and the page call the device.
    fn device_noun(&self) -> &str {
        "device"
    }
    /// The `protocol_settings` key that holds the device's ID.
    fn device_id_setting(&self) -> &str {
        "device_id"
    }
    /// The decoded keepalive field carrying the peer's own ID.
    fn peer_id_field(&self) -> &str {
        "device_id"
    }
}

/// The first six decoded fields, `k=v` with each value cut to 24 characters.
pub fn default_summary(msg: &Decoded) -> String {
    msg.fields.iter().take(6).map(|(k, v)| format!("{k}={}", pyfmt::head(&pyfmt::str(v), 24))).collect::<Vec<_>>().join(" ")
}

/// Split a datagram that carries several messages back to back, each starting with a label
/// (byte 0) and its own total length (byte `length_offset`). Trailing zero bytes are padding.
pub fn split_length_prefixed(data: &[u8], length_offset: usize, min_len: usize) -> Split {
    let mut parts = vec![];
    let mut o = 0;
    let n = data.len();
    while o < n {
        let rest = &data[o..];
        if rest.iter().all(|b| *b == 0) {
            return Split { parts, padding: rest.len(), problem: String::new() };
        }
        if rest.len() <= length_offset {
            parts.push(rest.to_vec());
            return Split { parts, padding: 0, problem: format!("{} trailing bytes too short for a length byte", rest.len()) };
        }
        let length = rest[length_offset] as usize;
        if length < min_len || length > rest.len() {
            parts.push(rest.to_vec());
            return Split {
                parts,
                padding: 0,
                problem: format!("length byte {length} at offset {o} does not fit the {} bytes left", rest.len()),
            };
        }
        parts.push(rest[..length].to_vec());
        o += length;
    }
    Split { parts, padding: 0, problem: String::new() }
}

/// A plugin's simulator: `main(argv) -> exit code`.
pub type SimMain = fn(Vec<String>) -> i32;
/// A plugin's constructor from `[sessions.<id>.protocol_settings]`.
pub type Create = fn(&Map<String, Value>) -> Result<Box<dyn Protocol>, String>;
/// A plugin's site-config check: an error refuses the config.
pub type ValidateSession = fn(&crate::config::SessionConfig) -> Result<(), String>;

/// One registered protocol.
#[derive(Clone)]
pub struct Plugin {
    pub name: String,
    pub create: Create,
    pub validate_session: Option<ValidateSession>,
    /// Simulators for `scapegoat sim <name>`.
    pub simulators: Vec<(String, SimMain)>,
    /// Profiles built into the binary: (name, file text). Listed by `scapegoat profiles`.
    pub profiles: Vec<(String, String)>,
    /// True for a protocol that ships with the open core.
    pub builtin: bool,
    /// Old config key names the plugin still accepts.
    pub config_aliases: ConfigAliases,
}

/// Old config key names a plugin still accepts, each `(old, new)`. Session aliases apply to
/// sessions using the plugin's protocol; feature aliases apply whenever the plugin is in the
/// binary. Setting both an old name and its new name is an error.
#[derive(Clone, Debug, Default)]
pub struct ConfigAliases {
    pub session: Vec<(String, String)>,
    pub features: Vec<(String, String)>,
}

/// The protocols compiled into this binary.
#[derive(Clone, Default)]
pub struct Registry {
    plugins: Vec<Plugin>,
    extension: crate::extension::Extension,
}

static REGISTRY: RwLock<Option<Arc<Registry>>> = RwLock::new(None);

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// Register a protocol. A later registration under the same name replaces the earlier.
    pub fn register(&mut self, p: Plugin) -> &mut Self {
        self.plugins.retain(|x| x.name != p.name);
        self.plugins.push(p);
        self
    }

    pub fn with(mut self, p: Plugin) -> Self {
        self.register(p);
        self
    }

    /// Give the registry site extension tables (`extension.rs`).
    pub fn with_extension(mut self, e: crate::extension::Extension) -> Self {
        self.extension = e;
        self
    }

    pub fn extension(&self) -> &crate::extension::Extension {
        &self.extension
    }

    pub fn get(&self, name: &str) -> Option<&Plugin> {
        self.plugins.iter().find(|p| p.name == name)
    }

    pub fn names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name.clone()).collect()
    }

    pub fn plugins(&self) -> &[Plugin] {
        &self.plugins
    }

    /// Make this the registry every lookup uses (the binary's `main` calls it once).
    pub fn install(self) {
        *REGISTRY.write().unwrap() = Some(Arc::new(self));
    }

    /// The installed registry (`toy` only if none was installed).
    pub fn current() -> Arc<Registry> {
        if let Some(r) = REGISTRY.read().unwrap().as_ref() {
            return r.clone();
        }
        let r = Arc::new(Registry::new().with(crate::toy::plugin()));
        *REGISTRY.write().unwrap() = Some(r.clone());
        r
    }

    /// The `(old, new)` key names for a config section: "session" (from `protocol`'s plugin)
    /// or "features" (from every plugin).
    pub fn config_aliases(&self, section: &str, protocol: Option<&str>) -> Vec<(String, String)> {
        let mut out: Vec<(String, String)> = vec![];
        for p in &self.plugins {
            if protocol.is_some_and(|n| n != p.name) {
                continue;
            }
            let table = if section == "session" { &p.config_aliases.session } else { &p.config_aliases.features };
            for (old, new) in table {
                out.retain(|(o, _)| o != old);
                out.push((old.clone(), new.clone()));
            }
        }
        out
    }

    /// {simulator name: (protocol, main)}, built-ins first.
    pub fn simulators(&self) -> Vec<(String, String, SimMain)> {
        let mut out: Vec<(String, String, SimMain)> = vec![];
        let mut ordered: Vec<&Plugin> = self.plugins.iter().filter(|p| p.builtin).collect();
        ordered.extend(self.plugins.iter().filter(|p| !p.builtin));
        for p in ordered {
            for (sim, main) in &p.simulators {
                if !out.iter().any(|(s, _, _)| s == sim) {
                    out.push((sim.clone(), p.name.clone(), *main));
                }
            }
        }
        out
    }
}

/// The named protocol could not be built.
#[derive(Debug)]
pub struct ProtocolError(pub String);

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 41
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// Build the Protocol for `name` from the registry.
pub fn load_protocol(name: &str, settings: &Map<String, Value>) -> Result<Box<dyn Protocol>, ProtocolError> {
    if !name_ok(name) {
        return Err(ProtocolError(format!("bad protocol name: {}", pyfmt::str_repr(name))));
    }
    let reg = Registry::current();
    match reg.get(name) {
        Some(p) => (p.create)(settings).map_err(|e| ProtocolError(format!("protocol {name} failed to start: {e}"))),
        None => {
            let exe = std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                .unwrap_or("scapegoat".into());
            Err(ProtocolError(format!(
                "protocol {} is not installed: this binary ({exe}) has {}. Install the binary built with that protocol's crate.",
                pyfmt::str_repr(name),
                reg.names().join(", ")
            )))
        }
    }
}
