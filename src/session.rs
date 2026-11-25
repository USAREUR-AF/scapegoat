// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! One sensor session: one UDP socket, the link state machine, counters, events.
//!
//! The socket is bound to the session's `local` address and used to send AND receive. The
//! sensor replies to the source address of our keepalives, so the two directions must share
//! one socket.
//!
//! States:
//!   disabled     -> not running (or turned off by an operator)
//!   handshaking  -> sending keepalives, nothing received yet
//!   establishing -> peer keepalives arriving, fewer than establish_after so far
//!   established  -> link up
//!   degraded     -> one expected peer keepalive missed
//!   lost         -> two consecutive peer keepalives missed (keeps sending)
//!
//! Peer candidates: until a sensor answers, every keepalive goes to EVERY candidate address,
//! each with its own LinkState (its own counters). The first candidate whose IP sends a valid
//! keepalive becomes the locked peer; the others are dropped until `reset` (or a forced
//! `lock`).

use crate::clock::{self, mono, now_iso, wall};
use crate::config::{fmt_addr, parse_addr_str, Addr, SessionConfig};
use crate::protocol::{load_protocol, ActionSpec, Decoded, LinkState, Protocol, ProtocolError, Track};
use crate::pyfmt;
use crate::traffic;
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

pub const STATES: [&str; 6] = ["disabled", "handshaking", "establishing", "established", "degraded", "lost"];
pub const EVENT_RING: usize = 500;
/// An armed dangerous control stays unlocked this long (one shot).
pub const ARM_WINDOW_S: f64 = 10.0;
/// A message that needs an answer is a PROBLEM if unanswered this long.
pub const OWED_REPLY_S: f64 = 5.0;
/// A forward target refusing this long is a PROBLEM.
pub const FORWARD_REFUSED_PROBLEM_S: f64 = 10.0;
/// A fresh forward socket (new source port) at least this often.
pub const FORWARD_ROTATE_S: f64 = 60.0;
pub const TRAFFIC_RING: usize = 2000;
pub const BIND_RETRY_S: f64 = 5.0;
pub const FOREIGN_LOG_EVERY_S: f64 = 60.0;
/// A repeated problem or peer request is logged at most this often.
pub const REPEAT_LOG_EVERY_S: f64 = 60.0;
/// Distinct problem strings kept in status.
pub const MAX_PROBLEMS: usize = 50;
pub const FEATURE_OFF_MSG: &str = "transmit control is disabled by feature flag (features.transmit_control = false)";
pub const KIND_SIM: &str = "SIMULATOR";

/// Why an action did not run, and the HTTP status the API answers with.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionError {
    /// A dangerous action was asked for without permission (HTTP 403).
    Refused(String),
    /// No such action for this session's protocol (HTTP 404).
    Unknown(String),
    /// The action could not be carried out (HTTP 400).
    Failed(String),
}

impl ActionError {
    pub fn status(&self) -> u16 {
        match self {
            ActionError::Refused(_) => 403,
            ActionError::Unknown(_) => 404,
            ActionError::Failed(_) => 400,
        }
    }
    pub fn message(&self) -> &str {
        match self {
            ActionError::Refused(m) | ActionError::Unknown(m) | ActionError::Failed(m) => m,
        }
    }
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// The socket copies to forward targets go out on.
pub trait FwdSock: Send {
    fn send_to(&self, data: &[u8], addr: &Addr) -> io::Result<usize>;
    /// The socket's source port, if it has one.
    fn local_port(&self) -> Option<u16> {
        None
    }
}

/// Resolve an `(host, port)` address to an IPv4 socket address, as Python's AF_INET sendto did.
pub fn resolve(addr: &Addr) -> io::Result<SocketAddr> {
    let it = (addr.0.as_str(), addr.1).to_socket_addrs()?;
    let mut first = None;
    for a in it {
        if a.is_ipv4() {
            return Ok(a);
        }
        first.get_or_insert(a);
    }
    first.ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address"))
}

struct UdpFwd(UdpSocket);

impl FwdSock for UdpFwd {
    fn send_to(&self, data: &[u8], addr: &Addr) -> io::Result<usize> {
        self.0.send_to(data, resolve(addr)?)
    }
    fn local_port(&self) -> Option<u16> {
        self.0.local_addr().ok().map(|a| a.port())
    }
}

/// A separate, unconnected UDP socket for copies to the forward targets. On Linux it asks for
/// ICMP errors (IP_RECVERR), so a refusing target shows up as ECONNREFUSED on the next send
/// instead of being silently ignored.
pub fn new_fwd_sock() -> Box<dyn FwdSock> {
    let s = UdpSocket::bind("0.0.0.0:0").expect("a UDP socket");
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVERR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    Box::new(UdpFwd(s))
}

#[derive(Clone, Debug)]
pub struct FwdState {
    pub refused_since: Option<f64>,
    pub last_refused: Option<f64>,
    pub last_ok: Option<f64>,
    pub errors: u64,
    pub last_error: String,
}

#[derive(Clone, Debug)]
pub struct Problem {
    pub count: u64,
    pub first: f64,
    pub last: f64,
    pub last_log: Option<f64>,
    pub logged_count: u64,
    pub messages: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Note {
    pub count: u64,
    pub first: f64,
    pub last: f64,
    pub messages: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PeerRequest {
    pub code: Option<i64>,
    pub count: u64,
    pub last: f64,
    pub last_log: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct Arm {
    pub token: String,
    pub until: f64,
    pub source: String,
    pub who: String,
}

#[derive(Clone, Debug)]
pub struct Owed {
    pub what: String,
    pub name: String,
    pub wall: f64,
    pub mono: f64,
}

pub type OnTracks = Arc<dyn Fn(&str, Vec<Track>) -> Result<(), String> + Send + Sync>;

/// An ordered map of small size (problem text, candidate address).
fn find<'a, K: PartialEq, V>(v: &'a [(K, V)], k: &K) -> Option<&'a V> {
    v.iter().find(|(x, _)| x == k).map(|(_, v)| v)
}

/// The session's state. Held under the session's lock; tests read it through `Session::with`.
pub struct Inner {
    me: Weak<Mutex<Inner>>,
    pub cfg: SessionConfig,
    pub id: String,
    pub events: VecDeque<Map<String, Value>>,
    pub traffic: VecDeque<Map<String, Value>>,
    pub arms: Vec<(String, Arm)>,
    pub on_tracks: Option<OnTracks>,
    pub tracks_out: u64,
    pub fwd_state: Vec<(Addr, FwdState)>,
    pub fwd_sock_replaced: u64,
    fwd_replace_logged: f64,
    fwd_rotated: f64,
    pub owed: Vec<Owed>,
    pub owed_answered: u64,
    pub owed_missed: u64,
    pub traffic_seq: u64,
    pub error: String,
    pub protocol: Option<Box<dyn Protocol>>,
    pub interval: f64,
    pub establish_after: u64,
    pub margin: f64,
    pub candidates: Vec<Addr>,
    pub local: Addr,
    pub forward: Vec<Addr>,
    pub noun: String,
    pub kind_none: String,
    pub kind_real: String,
    pub device_id: i64,
    pub links: Vec<(Addr, LinkState)>,
    pub locked: Option<Addr>,
    pub forced: bool,
    pub sock: Option<UdpSocket>,
    pub fwd_sock: Option<Box<dyn FwdSock>>,
    /// Builds a forward socket; tests replace it.
    pub fwd_factory: fn() -> Box<dyn FwdSock>,
    rx_thread: Option<JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
    pub enabled: bool,
    last_bind_try: f64,
    last_foreign_log: f64,
    pub rx_datagrams: u64,
    pub tx_datagrams: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub bad_datagrams: u64,
    pub foreign_datagrams: u64,
    pub forwarded: u64,
    pub forward_errors: u64,
    pub send_errors: u64,
    pub rx_by_name: Vec<(String, u64)>,
    pub rx_messages: u64,
    pub multi_message_datagrams: u64,
    pub notes: Vec<(String, Note)>,
    pub datagram_seq: u64,
    pub tx_by_name: Vec<(String, u64)>,
    pub ka_streak: u64,
    pub ka_rx_total: u64,
    pub problems: Vec<(String, Problem)>,
    pub peer_requests: Vec<(String, PeerRequest)>,
    pub peer_request: Option<String>,
    pub peer_status: Vec<(String, String)>,
    pub peer_status_at: Option<f64>,
    pub peer_urn: Option<Value>,
    pub peer_device_id: Option<Value>,
    kind_logged: Option<String>,
    pub last_rx: Option<f64>,
    pub last_tx: Option<f64>,
    pub last_ka_rx: Option<f64>,
    pub peer_seen: Option<Addr>,
    pub next_ka_due: f64,
    pub state_since: f64,
    pub state: String,
    /// The arm window and the owed-reply limit (constants above; tests shorten them).
    pub arm_window_s: f64,
    pub owed_reply_s: f64,
}

/// One sensor session. Cheap to clone: every clone is the same session.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Mutex<Inner>>,
    pub id: String,
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn bump(v: &mut Vec<(String, u64)>, k: &str) {
    if let Some((_, n)) = v.iter_mut().find(|(x, _)| x == k) {
        *n += 1;
    } else {
        v.push((k.to_string(), 1));
    }
}

/// Python `str.format(**vals)` for `{name}` placeholders; anything else leaves the text as is.
pub fn format_named(text: &str, vals: &[(String, Value)]) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut name = String::new();
                let mut closed = false;
                for d in chars.by_ref() {
                    if d == '}' {
                        closed = true;
                        break;
                    }
                    name.push(d);
                }
                let key = name.split([':', '!']).next().unwrap_or("");
                match (closed, vals.iter().rev().find(|(k, _)| k == key)) {
                    (true, Some((_, v))) => out.push_str(&pyfmt::str(v)),
                    _ => return text.to_string(),
                }
            }
            '}' => return text.to_string(),
            c => out.push(c),
        }
    }
    out
}

fn age(now: f64, t: Option<f64>) -> Value {
    match t {
        None => Value::Null,
        Some(t) => json!(pyfmt::round(now - t, 2)),
    }
}

impl Session {
    /// A session for `cfg`, with its protocol from the registry unless one is given.
    pub fn new(cfg: SessionConfig, protocol: Option<Box<dyn Protocol>>) -> Session {
        let id = cfg.id.clone();
        let inner = Arc::new_cyclic(|me| Mutex::new(Inner::new(me.clone(), cfg, protocol)));
        Session { inner, id }
    }

    /// Read or change the session's state under its lock.
    pub fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut lock(&self.inner))
    }

    pub fn state(&self) -> String {
        self.with(|i| i.state.clone())
    }

    pub fn interval(&self) -> f64 {
        self.with(|i| i.interval)
    }

    pub fn start(&self) {
        self.with(|i| {
            if i.enabled {
                i.open();
            }
        });
    }

    pub fn stop(&self) {
        let t = self.with(|i| i.close());
        join(t);
    }

    pub fn enable(&self, source: &str) -> Result<(), ActionError> {
        self.with(|i| {
            if i.protocol.is_none() {
                return Err(ActionError::Failed(if i.error.is_empty() { "protocol not loaded".into() } else { i.error.clone() }));
            }
            i.event("action", "enable", "info", source);
            i.enabled = true;
            i.open();
            Ok(())
        })
    }

    pub fn disable(&self, source: &str) {
        let t = self.with(|i| {
            i.event("action", "disable", "info", source);
            i.enabled = false;
            let t = i.close();
            i.set_state("disabled", &format!("disabled by {source}"));
            t
        });
        join(t);
    }

    pub fn reset(&self, source: &str) {
        self.with(|i| i.reset(source))
    }

    pub fn force_lock(&self, addr_text: &str, source: &str) -> Result<(), ActionError> {
        self.with(|i| i.force_lock(addr_text, source))
    }

    pub fn tick(&self, now: Option<f64>) {
        self.with(|i| i.tick(now.unwrap_or_else(mono)))
    }

    /// Handle one datagram as if it had arrived from `addr`.
    pub fn handle(&self, data: &[u8], addr: &Addr) {
        self.with(|i| i.handle(data, addr))
    }

    pub fn get_traffic(&self, since: Option<i64>, limit: i64) -> Value {
        let limit = limit.clamp(1, 2000) as usize;
        let (items, last) = self.with(|i| (i.traffic.iter().cloned().collect::<Vec<_>>(), i.traffic_seq));
        let items: Vec<Map<String, Value>> = match since {
            None => {
                let n = items.len();
                items.into_iter().skip(n.saturating_sub(limit)).collect()
            }
            Some(s) => items.into_iter().filter(|e| e["seq"].as_i64().unwrap_or(0) > s).take(limit).collect(),
        };
        json!({"session": self.id, "last_seq": last, "entries": items})
    }

    /// Capture the session's UDP port from the wire and decode every payload.
    pub fn wire(&self, seconds: f64, iface: &str) -> Value {
        let port = self.with(|i| i.local.1);
        let cap = traffic::wire_capture(port, seconds, iface);
        self.with(|i| {
            let now = mono();
            for u in &cap.unreachable {
                i.note_problem(u["hint"].as_str().unwrap_or(""), now, "ICMP");
            }
            let mut entries = vec![];
            for (n, p) in cap.packets.iter().enumerate() {
                let msg = i.protocol.is_some().then(|| i.decode(&p.payload));
                let mut e = traffic::make_entry("wire", &p.src, &p.payload, msg.as_ref(), None);
                e.insert("seq".into(), json!(n + 1));
                e.insert("src".into(), json!(p.src));
                e.insert("dst".into(), json!(p.dst));
                e.insert("capture_time".into(), json!(p.time));
                entries.push(Value::Object(e));
            }
            json!({
                "session": i.id, "port": port, "seconds": seconds, "entries": entries,
                "error": cap.error, "icmp_unreachable": cap.unreachable,
                "hints": cap.unreachable.iter().map(|u| u["hint"].clone()).collect::<Vec<_>>(),
            })
        })
    }

    pub fn actions(&self) -> Vec<ActionSpec> {
        self.with(|i| i.actions())
    }

    pub fn arm(&self, name: &str, source: &str, who: &str, args: &Map<String, Value>) -> Result<Value, ActionError> {
        self.with(|i| i.arm(name, source, who, args))
    }

    pub fn disarm(&self, name: &str, source: &str, who: &str) -> Value {
        self.with(|i| i.disarm(name, source, who))
    }

    pub fn run_action(
        &self,
        name: &str,
        confirm: &Value,
        source: &str,
        args: &Map<String, Value>,
        token: Option<&str>,
        who: &str,
    ) -> Result<Value, ActionError> {
        self.with(|i| i.run_action(name, confirm, source, args, token, who))
    }

    pub fn status(&self, events: usize) -> Value {
        self.with(|i| i.status(events))
    }

    pub fn local_seen_as(&self) -> String {
        self.with(|i| i.local_seen_as())
    }

    pub fn get_events(&self, n: i64) -> Vec<Value> {
        self.with(|i| {
            let n = n.max(0) as usize;
            let skip = i.events.len().saturating_sub(n);
            i.events.iter().skip(skip).cloned().map(Value::Object).collect()
        })
    }

    pub fn set_on_tracks(&self, f: OnTracks) {
        self.with(|i| i.on_tracks = Some(f));
    }
}

fn join(t: Option<JoinHandle<()>>) {
    if let Some(t) = t {
        if t.thread().id() != std::thread::current().id() {
            let _ = t.join();
        }
    }
}

fn rx_loop(me: Weak<Mutex<Inner>>, sock: UdpSocket, stop: Arc<AtomicBool>) {
    let mut buf = vec![0u8; 65535];
    while !stop.load(Ordering::Relaxed) {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => continue,
            Err(_) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Some(inner) = me.upgrade() else { return };
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let addr: Addr = (from.ip().to_string(), from.port());
        let data = buf[..n].to_vec();
        let r = catch_unwind(AssertUnwindSafe(|| lock(&inner).handle(&data, &addr)));
        if let Err(p) = r {
            // never let one bad datagram kill the thread
            let what = p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            lock(&inner).event("error", &format!("handling datagram from ('{}', {}): {what}", addr.0, addr.1), "error", "core");
        }
    }
}

impl Inner {
    fn new(me: Weak<Mutex<Inner>>, cfg: SessionConfig, protocol: Option<Box<dyn Protocol>>) -> Inner {
        let mut error = String::new();
        let protocol = match protocol {
            Some(p) => Some(p),
            None => match catch_unwind(AssertUnwindSafe(|| load_protocol(&cfg.protocol, &cfg.protocol_settings))) {
                Ok(Ok(p)) => Some(p),
                Ok(Err(ProtocolError(e))) => {
                    error = e;
                    None
                }
                Err(_) => {
                    error = format!("protocol {} failed to start", cfg.protocol);
                    None
                }
            },
        };
        let ps = cfg.protocol_settings.clone();
        let default_iv = protocol.as_ref().map(|p| p.keepalive_interval_s()).unwrap_or(30.0);
        let interval = ps.get("keepalive_interval_s").and_then(Value::as_f64).unwrap_or(default_iv);
        let establish_after = ps.get("establish_after").and_then(Value::as_f64).map(|f| f.trunc() as i64).unwrap_or(3).max(1) as u64;
        let candidates = cfg.candidate_addrs().unwrap_or_default();
        let mut local = cfg.local_addr().unwrap_or(("0.0.0.0".into(), 0));
        if cfg.local.is_empty() {
            local = ("0.0.0.0".into(), protocol.as_ref().map(|p| p.default_port()).unwrap_or(0));
        }
        let forward = cfg.forward_addrs().unwrap_or_default();
        let noun = protocol.as_ref().map(|p| p.device_noun().to_string()).unwrap_or("device".into());
        let id_key = protocol.as_ref().map(|p| p.device_id_setting().to_string()).unwrap_or("device_id".into());
        let device_id = match ps.get(&id_key) {
            Some(Value::Number(n)) => n.as_f64().map(|f| f.trunc() as i64).unwrap_or(0),
            Some(Value::String(s)) => crate::config::py_int(s).unwrap_or(0),
            Some(Value::Bool(b)) => *b as i64,
            _ => 0,
        };
        let enabled = cfg.enabled && protocol.is_some();
        let mut s = Inner {
            me,
            id: cfg.id.clone(),
            events: VecDeque::new(),
            traffic: VecDeque::new(),
            arms: vec![],
            on_tracks: None,
            tracks_out: 0,
            fwd_state: vec![],
            fwd_sock_replaced: 0,
            fwd_replace_logged: 0.0,
            fwd_rotated: mono(),
            owed: vec![],
            owed_answered: 0,
            owed_missed: 0,
            traffic_seq: 0,
            error,
            protocol,
            interval,
            establish_after,
            margin: 0.25 * interval,
            candidates,
            local,
            forward,
            kind_none: format!("no {noun} yet"),
            kind_real: format!("REAL {}", noun.to_uppercase()),
            noun,
            device_id,
            links: vec![],
            locked: None,
            forced: false,
            sock: None,
            fwd_sock: None,
            fwd_factory: new_fwd_sock,
            rx_thread: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            enabled,
            last_bind_try: 0.0,
            last_foreign_log: 0.0,
            rx_datagrams: 0,
            tx_datagrams: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            bad_datagrams: 0,
            foreign_datagrams: 0,
            forwarded: 0,
            forward_errors: 0,
            send_errors: 0,
            rx_by_name: vec![],
            rx_messages: 0,
            multi_message_datagrams: 0,
            notes: vec![],
            datagram_seq: 0,
            tx_by_name: vec![],
            ka_streak: 0,
            ka_rx_total: 0,
            problems: vec![],
            peer_requests: vec![],
            peer_request: None,
            peer_status: vec![],
            peer_status_at: None,
            peer_urn: None,
            peer_device_id: None,
            kind_logged: None,
            last_rx: None,
            last_tx: None,
            last_ka_rx: None,
            peer_seen: None,
            next_ka_due: 0.0,
            state_since: mono(),
            state: "disabled".into(),
            arm_window_s: ARM_WINDOW_S,
            owed_reply_s: OWED_REPLY_S,
            cfg,
        };
        s.reset_counters();
        if !s.error.is_empty() {
            let e = s.error.clone();
            s.event("error", &e, "error", "core");
        }
        s
    }

    // ------------------------------------------------------------------ peers
    fn new_link(&self) -> LinkState {
        LinkState { device_id: self.device_id, settings: self.cfg.protocol_settings.clone(), ..Default::default() }
    }

    /// The locked peer's address, or the first candidate's while probing.
    pub fn peer(&self) -> Option<Addr> {
        self.locked.clone().or_else(|| self.candidates.first().cloned())
    }

    /// The locked peer's link, or the first candidate's while probing.
    pub fn link(&self) -> LinkState {
        self.peer().and_then(|p| find(&self.links, &p).cloned()).unwrap_or_default()
    }

    pub fn link_of(&self, a: &Addr) -> Option<&LinkState> {
        find(&self.links, a)
    }

    fn link_mut(&mut self, a: &Addr) -> &mut LinkState {
        if !self.links.iter().any(|(x, _)| x == a) {
            let l = self.new_link();
            self.links.push((a.clone(), l));
        }
        &mut self.links.iter_mut().find(|(x, _)| x == a).unwrap().1
    }

    fn targets(&self) -> Vec<Addr> {
        match &self.locked {
            Some(l) => vec![l.clone()],
            None => self.candidates.clone(),
        }
    }

    fn candidate_for(&self, ip: &str) -> Option<Addr> {
        self.targets().into_iter().find(|c| c.0 == ip)
    }

    // ------------------------------------------------------------------ counters
    fn reset_counters(&mut self) {
        self.candidates = self.cfg.candidate_addrs().unwrap_or_default();
        self.links = self.candidates.iter().map(|c| (c.clone(), self.new_link())).collect();
        self.locked = None;
        self.forced = false;
        self.rx_datagrams = 0;
        self.tx_datagrams = 0;
        self.rx_bytes = 0;
        self.tx_bytes = 0;
        self.bad_datagrams = 0;
        self.foreign_datagrams = 0;
        self.forwarded = 0;
        self.forward_errors = 0;
        self.send_errors = 0;
        self.rx_by_name.clear();
        self.rx_messages = 0;
        self.multi_message_datagrams = 0;
        self.notes.clear();
        self.datagram_seq = 0;
        self.tx_by_name.clear();
        self.ka_streak = 0;
        self.ka_rx_total = 0;
        self.problems.clear();
        self.peer_requests.clear();
        self.peer_request = None;
        self.peer_status.clear();
        self.peer_status_at = None;
        self.peer_urn = None;
        self.peer_device_id = None;
        self.kind_logged = None;
        self.last_rx = None;
        self.last_tx = None;
        self.last_ka_rx = None;
        self.peer_seen = None;
        self.next_ka_due = 0.0;
        self.state_since = mono();
    }

    // ------------------------------------------------------------------ events
    pub fn event(&mut self, kind: &str, msg: &str, level: &str, source: &str) {
        let ev = json!({"time": now_iso(), "ts": wall(), "kind": kind, "level": level, "source": source, "message": msg});
        if self.events.len() == EVENT_RING {
            self.events.pop_front();
        }
        self.events.push_back(ev.as_object().unwrap().clone());
        let lvl = match level {
            "warn" => crate::log::Level::Warning,
            "error" => crate::log::Level::Error,
            _ => crate::log::Level::Info,
        };
        crate::log::log(lvl, "scapegoat.session", &format!("[{}] {kind} ({source}): {msg}", self.id));
    }

    pub fn set_state(&mut self, new: &str, why: &str) {
        if new != self.state {
            let old = std::mem::replace(&mut self.state, new.to_string());
            self.state_since = mono();
            let level = if new == "degraded" || new == "lost" { "warn" } else { "info" };
            self.event("state", &format!("{old} -> {new}: {why}"), level, "core");
        }
    }

    // ------------------------------------------------------------------ lifecycle
    fn open(&mut self) -> bool {
        if self.sock.is_some() {
            return true;
        }
        self.last_bind_try = mono();
        let opened = (|| -> io::Result<UdpSocket> {
            let addr = resolve(&self.local)?;
            let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            s.set_reuse_address(true)?;
            s.bind(&addr.into())?;
            let s: UdpSocket = s.into();
            s.set_read_timeout(Some(Duration::from_millis(250)))?;
            Ok(s)
        })();
        let s = match opened {
            Ok(s) => s,
            Err(e) => {
                let msg =
                    format!("cannot open UDP {}: {}. Retrying every {:.0} s.", fmt_addr(&self.local), pyfmt::os_error(&e), BIND_RETRY_S);
                if self.error != msg {
                    self.error = msg.clone();
                    self.event("error", &msg, "error", "core");
                }
                self.set_state("handshaking", "waiting for the local UDP port");
                return false;
            }
        };
        let rx = s.try_clone().expect("a second handle on the session socket");
        self.sock = Some(s);
        self.fwd_sock = if self.forward.is_empty() { None } else { Some((self.fwd_factory)()) };
        self.error.clear();
        self.stop_flag = Arc::new(AtomicBool::new(false));
        let (me, stop) = (self.me.clone(), self.stop_flag.clone());
        self.rx_thread = Some(
            std::thread::Builder::new().name(format!("scapegoat-rx-{}", self.id)).spawn(move || rx_loop(me, rx, stop)).expect("rx thread"),
        );
        let peers = self.targets().iter().map(fmt_addr).collect::<Vec<_>>().join(", ");
        let msg = format!("listening on {}, peer {peers}", fmt_addr(&self.local));
        self.event("socket", &msg, "info", "core");
        self.next_ka_due = 0.0; // send the first keepalive now
        self.set_state("handshaking", "socket open, sending keepalives");
        true
    }

    /// Close the sockets; the caller joins the returned receive thread after unlocking.
    fn close(&mut self) -> Option<JoinHandle<()>> {
        self.stop_flag.store(true, Ordering::Relaxed);
        self.sock = None;
        self.fwd_sock = None;
        self.rx_thread.take()
    }

    pub fn reset(&mut self, source: &str) {
        self.event("action", "reset (counters to 0, unlock peer, state handshaking)", "info", source);
        self.reset_counters();
        if self.enabled && self.sock.is_some() {
            self.set_state("handshaking", &format!("reset by {source}"));
        } else if !self.enabled {
            self.set_state("disabled", "reset while disabled");
        }
    }

    /// Lock onto one address now (it is added if it is not a candidate).
    pub fn force_lock(&mut self, addr_text: &str, source: &str) -> Result<(), ActionError> {
        let addr = parse_addr_str(addr_text, "peer").map_err(|e| ActionError::Failed(e.0))?;
        if !self.candidates.contains(&addr) {
            self.candidates.push(addr.clone());
        }
        self.link_mut(&addr);
        self.locked = Some(addr.clone());
        self.forced = true;
        self.last_ka_rx = None;
        self.ka_streak = 0;
        self.next_ka_due = 0.0;
        self.event(
            "lock",
            &format!("locked onto {} (forced by {source}); not sending to other candidates", fmt_addr(&addr)),
            "info",
            source,
        );
        if self.enabled && self.sock.is_some() {
            self.set_state("handshaking", &format!("forced lock by {source}"));
        }
        Ok(())
    }

    fn auto_lock(&mut self, cand: &Addr, addr: &Addr) {
        self.locked = Some(cand.clone());
        self.forced = false;
        let others: Vec<String> = self.candidates.iter().filter(|c| *c != cand).map(fmt_addr).collect();
        let msg = format!("locked onto {}", fmt_addr(addr))
            + &if others.is_empty() { String::new() } else { format!("; stopped sending to {}", others.join(", ")) };
        self.event("lock", &msg, "info", "core");
    }

    // ------------------------------------------------------------------ sending
    pub fn decode(&mut self, data: &[u8]) -> Decoded {
        let Some(p) = self.protocol.as_mut() else { return Decoded::problem("protocol not loaded") };
        match catch_unwind(AssertUnwindSafe(|| p.decode(data))) {
            Ok(m) => m,
            Err(e) => {
                let what =
                    e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                Decoded::problem(format!("decoder error: {what}"))
            }
        }
    }

    fn record(
        &mut self,
        direction: &str,
        addr: &Addr,
        data: &[u8],
        msg: Option<&Decoded>,
        extra_problem: &str,
        extra: Option<Map<String, Value>>,
    ) {
        let mut e = traffic::make_entry(direction, &fmt_addr(addr), data, msg, None);
        if !extra_problem.is_empty() {
            if let Some(Value::Array(a)) = e.get_mut("problems") {
                a.push(json!(extra_problem));
            }
        }
        if let Some(m) = msg {
            if !m.notes.is_empty() {
                e.insert("notes".into(), json!(m.notes));
            }
            if let Some(p) = self.protocol.as_ref() {
                if let Ok(Ok(s)) = catch_unwind(AssertUnwindSafe(|| p.summarize(m))) {
                    e.insert("summary".into(), json!(s));
                }
            }
        }
        if let Some(x) = extra {
            for (k, v) in x {
                e.insert(k, v);
            }
        }
        self.traffic_seq += 1;
        e.insert("seq".into(), json!(self.traffic_seq));
        self.push_traffic(e);
    }

    fn push_traffic(&mut self, e: Map<String, Value>) {
        if self.traffic.len() == TRAFFIC_RING {
            self.traffic.pop_front();
        }
        self.traffic.push_back(e);
    }

    fn send(&mut self, data: &[u8], addr: &Addr, why: &str) -> bool {
        let Some(sock) = self.sock.as_ref() else { return false };
        let r = resolve(addr).and_then(|a| sock.send_to(data, a));
        if let Err(e) = r {
            self.send_errors += 1;
            self.event("error", &format!("send to {}:{} failed ({why}): {}", addr.0, addr.1, pyfmt::os_error(&e)), "error", "core");
            return false;
        }
        self.tx_datagrams += 1;
        self.tx_bytes += data.len() as u64;
        self.last_tx = Some(mono());
        // Same rule as received copies: a message we built that is self-consistent by its own
        // length byte shows dictionary drift as a note, not a failure.
        let msg = self.decode_part(data);
        let name = if msg.name.is_empty() { "unknown".to_string() } else { msg.name.clone() };
        bump(&mut self.tx_by_name, &name);
        self.record("tx", addr, data, Some(&msg), "", None);
        true
    }

    /// Called often by the scheduler: send due keepalives, check for misses.
    pub fn tick(&mut self, now: f64) {
        if !self.enabled {
            return;
        }
        if self.sock.is_none() {
            if now - self.last_bind_try >= BIND_RETRY_S {
                self.open();
            }
            if self.sock.is_none() {
                return;
            }
        }
        if now >= self.next_ka_due {
            for c in self.targets() {
                let link_idx = self.links.iter().position(|(x, _)| *x == c);
                let r = match (self.protocol.as_mut(), link_idx) {
                    (Some(p), Some(i)) => {
                        let link = &mut self.links[i].1;
                        catch_unwind(AssertUnwindSafe(|| p.keepalive(link, 0))).unwrap_or_else(|_| Err("panic".into()))
                    }
                    _ => Err("no link".into()),
                };
                match r {
                    Ok(data) if !data.is_empty() => {
                        self.send(&data, &c, "keepalive");
                    }
                    Ok(_) => {}
                    Err(e) => self.event("error", &format!("building keepalive failed: {e}"), "error", "core"),
                }
            }
            self.next_ka_due = now + self.interval;
        }
        self.expire_arms(now);
        self.periodic(now);
        self.check_owed(now);
        self.check_forwards(now);
        self.check_missed(now);
    }

    /// Protocol messages that are due (e.g. a timing message every 60 s) once a peer is locked.
    fn periodic(&mut self, now: f64) {
        if let Some(locked) = self.locked.clone() {
            let idx = self.links.iter().position(|(x, _)| *x == locked);
            let due = match (self.protocol.as_mut(), idx) {
                (Some(p), Some(i)) => {
                    let link = &mut self.links[i].1;
                    catch_unwind(AssertUnwindSafe(|| p.periodic(link, now))).unwrap_or_else(|_| Err("panic".into()))
                }
                _ => Ok(vec![]),
            };
            match due {
                Ok(d) => {
                    for x in d {
                        self.send(&x, &locked, "periodic");
                    }
                }
                Err(e) => self.event("error", &format!("protocol periodic failed: {e}"), "error", "core"),
            }
        }
        let texts = self.protocol.as_mut().map(|p| p.drain_events()).unwrap_or_default();
        for t in texts {
            self.event("protocol", &t, "info", "core");
        }
    }

    fn check_owed(&mut self, now: f64) {
        let mut keep = vec![];
        for o in std::mem::take(&mut self.owed) {
            if now - o.mono > self.owed_reply_s {
                self.owed_missed += 1;
                let text = format!("owed: {} for {} from the {} at {}Z, unanswered", o.what, o.name, self.noun, clock::hhmmss(o.wall));
                self.note_problem(&text, now, &o.name);
            } else {
                keep.push(o);
            }
        }
        self.owed = keep;
    }

    fn check_missed(&mut self, now: f64) {
        if self.state == "disabled" || self.state == "handshaking" {
            return;
        }
        let Some(last) = self.last_ka_rx else { return };
        let silent = now - last;
        if silent > 2.0 * self.interval + self.margin {
            if self.state != "lost" {
                self.ka_streak = 0;
                self.set_state("lost", &format!("no keepalive from peer for {silent:.1} s (two missed); still sending keepalives"));
            }
        } else if silent > self.interval + self.margin && self.state != "degraded" && self.state != "lost" {
            self.ka_streak = 0;
            self.set_state("degraded", &format!("one keepalive from peer missed ({silent:.1} s)"));
        }
    }

    // ------------------------------------------------------------------ receiving
    pub fn handle(&mut self, data: &[u8], addr: &Addr) {
        let now = mono();
        let Some(cand) = self.candidate_for(&addr.0) else {
            self.foreign_datagrams += 1;
            let msg = self.decode(data);
            self.record("rx", addr, data, Some(&msg), "ignored: not from a peer candidate", None);
            if now - self.last_foreign_log > FOREIGN_LOG_EVERY_S {
                self.last_foreign_log = now;
                let want = self.targets().iter().map(|c| c.0.clone()).collect::<Vec<_>>().join(", ");
                self.event("foreign", &format!("ignored datagram from {}:{} (expected {want})", addr.0, addr.1), "warn", "core");
            }
            return;
        };
        self.rx_datagrams += 1;
        self.rx_bytes += data.len() as u64;
        self.last_rx = Some(now);
        if self.peer_seen.as_ref() != Some(addr) && (self.locked.is_none() || self.locked.as_ref() == Some(&cand)) {
            self.event("peer", &format!("peer answering from {}:{}", addr.0, addr.1), "info", "core");
            self.peer_seen = Some(addr.clone());
        }
        let (parts, padding, split_problem) = self.split(data);
        self.datagram_seq += 1;
        let dg = self.datagram_seq;
        let msgs: Vec<Decoded> = parts.iter().map(|p| self.decode_part(p)).collect();
        if parts.len() > 1 || padding > 0 || !split_problem.is_empty() {
            if parts.len() > 1 {
                self.multi_message_datagrams += 1;
            }
            let list: Vec<String> = msgs
                .iter()
                .zip(&parts)
                .map(|(m, p)| format!("{} ({} B)", if m.name.is_empty() { "unknown" } else { &m.name }, p.len()))
                .collect();
            let mut f = Map::new();
            f.insert("messages".into(), json!(list));
            f.insert("padding_bytes".into(), json!(padding));
            let summary = Decoded::new(
                &format!("datagram: {} message(s)", parts.len()),
                f,
                split_problem.is_empty(),
                if split_problem.is_empty() { vec![] } else { vec![split_problem.clone()] },
                false,
                None,
            );
            let mut x = Map::new();
            x.insert("datagram".into(), json!(dg));
            self.record("dgram", addr, data, Some(&summary), "", Some(x));
            if !split_problem.is_empty() {
                self.note_problem(&split_problem, now, "datagram");
            }
        }
        if self.cfg.forward_mode == "datagram" {
            let m = if msgs.len() == 1 {
                msgs[0].clone()
            } else {
                Decoded::new(&format!("datagram: {} message(s)", parts.len()), Map::new(), true, vec![], false, None)
            };
            self.forward_copy(data, &m);
        }
        let n = parts.len();
        for (i, (part, msg)) in parts.iter().zip(msgs).enumerate() {
            let mut x = Map::new();
            x.insert("datagram".into(), json!(dg));
            x.insert("part".into(), json!(i + 1));
            x.insert("parts".into(), json!(n));
            x.insert("datagram_length".into(), json!(data.len()));
            self.record("rx", addr, part, Some(&msg), "", Some(x));
            if self.cfg.forward_mode == "message" {
                self.forward_copy(part, &msg);
            }
            self.handle_message(part, msg, addr, &cand, now);
        }
    }

    /// Messages in one datagram (the protocol's `split`, if it has one).
    fn split(&mut self, data: &[u8]) -> (Vec<Vec<u8>>, usize, String) {
        let Some(p) = self.protocol.as_mut() else { return (vec![data.to_vec()], 0, String::new()) };
        match catch_unwind(AssertUnwindSafe(|| p.split(data))) {
            Ok(None) => (vec![data.to_vec()], 0, String::new()),
            Ok(Some(Ok(s))) => {
                let parts = if s.parts.is_empty() { vec![data.to_vec()] } else { s.parts };
                (parts, s.padding, s.problem)
            }
            Ok(Some(Err(e))) => (vec![data.to_vec()], 0, format!("split failed: {e}")),
            Err(_) => (vec![data.to_vec()], 0, "split failed".into()),
        }
    }

    fn decode_part(&mut self, part: &[u8]) -> Decoded {
        let mut msg = self.decode(part);
        let notes = self
            .protocol
            .as_ref()
            .map(|p| catch_unwind(AssertUnwindSafe(|| p.soften_problems(part, &mut msg))).unwrap_or_default())
            .unwrap_or_default();
        msg.notes = notes;
        msg
    }

    /// A fresh socket (new source port) after a send error, and periodically. Hygiene: it
    /// keeps one broken socket from holding the forward path.
    fn replace_fwd_sock(&mut self, why: &str, quiet: bool) {
        self.fwd_sock = Some((self.fwd_factory)());
        self.fwd_rotated = mono();
        if quiet {
            return;
        }
        self.fwd_sock_replaced += 1;
        let now = mono();
        if now - self.fwd_replace_logged > 5.0 {
            self.fwd_replace_logged = now;
            self.event("forward", &format!("forward socket replaced ({why})"), "warn", "core");
        }
    }

    fn fwd_entry(&mut self, f: &Addr) -> &mut FwdState {
        if !self.fwd_state.iter().any(|(x, _)| x == f) {
            self.fwd_state.push((
                f.clone(),
                FwdState { refused_since: None, last_refused: None, last_ok: None, errors: 0, last_error: String::new() },
            ));
        }
        &mut self.fwd_state.iter_mut().find(|(x, _)| x == f).unwrap().1
    }

    fn note_fwd_error(&mut self, f: &Addr, e: &io::Error, now: f64) {
        self.forward_errors += 1;
        let st = self.fwd_entry(f);
        st.errors += 1;
        st.last_error = pyfmt::os_error(e);
        if e.kind() == io::ErrorKind::ConnectionRefused {
            st.last_refused = Some(now);
            if st.refused_since.is_none() {
                st.refused_since = Some(now);
            }
        }
    }

    fn forward_copy(&mut self, data: &[u8], msg: &Decoded) {
        let now = mono();
        for f in self.forward.clone() {
            if self.fwd_sock.is_none() {
                self.replace_fwd_sock("no forward socket", false);
            }
            self.fwd_entry(&f);
            let r = self.fwd_sock.as_ref().unwrap().send_to(data, &f);
            if let Err(e) = r {
                // count only what was really sent; any error: count, log, new socket, retry once
                self.note_fwd_error(&f, &e, now);
                let text = pyfmt::os_error(&e);
                self.record("fwd", &f, data, Some(msg), &format!("forward failed: {text}"), None);
                self.replace_fwd_sock(&format!("send to {}:{} failed: {text}", f.0, f.1), false);
                if let Err(e2) = self.fwd_sock.as_ref().unwrap().send_to(data, &f) {
                    self.note_fwd_error(&f, &e2, now);
                    continue;
                }
            }
            self.forwarded += 1;
            self.fwd_entry(&f).last_ok = Some(now);
            self.record("fwd", &f, data, Some(msg), "", None);
        }
    }

    /// PROBLEM while a forward target keeps refusing sends for more than 10 s. A refused send
    /// is retried on a new socket, so the kernel may still accept copies in between: what
    /// counts is that refusals keep arriving. Also replaces the forward socket every
    /// FORWARD_ROTATE_S.
    pub fn check_forwards(&mut self, now: f64) {
        if self.fwd_sock.is_some() && now - self.fwd_rotated >= FORWARD_ROTATE_S {
            self.fwd_rotated = now;
            self.replace_fwd_sock("periodic rotation", true);
        }
        let mut problems = vec![];
        for (f, st) in self.fwd_state.iter_mut() {
            let Some(since) = st.refused_since else { continue };
            if now - st.last_refused.unwrap_or(since) > FORWARD_REFUSED_PROBLEM_S {
                st.refused_since = None; // no refusal for 10 s: the target is back
                continue;
            }
            if now - since > FORWARD_REFUSED_PROBLEM_S {
                problems.push(format!(
                    "forward target {}:{}: receiver not receiving for more than {} s (check the kid's port forwarding: billie kid activate)",
                    f.0,
                    f.1,
                    pyfmt::g(FORWARD_REFUSED_PROBLEM_S)
                ));
            }
        }
        for p in problems {
            self.note_problem(&p, now, "forward");
        }
    }

    fn note_soft(&mut self, text: &str, now: f64, where_: &str) {
        if !self.notes.iter().any(|(k, _)| k == text) {
            if self.notes.len() >= MAX_PROBLEMS {
                let oldest = self.notes.iter().enumerate().min_by(|a, b| a.1 .1.last.total_cmp(&b.1 .1.last)).map(|(i, _)| i).unwrap();
                self.notes.remove(oldest);
            }
            self.notes.push((text.to_string(), Note { count: 0, first: now, last: now, messages: vec![] }));
            self.event("note", &format!("{text} [in {where_}]"), "info", "core");
        }
        let n = &mut self.notes.iter_mut().find(|(k, _)| k == text).unwrap().1;
        if !where_.is_empty() && !n.messages.iter().any(|m| m == where_) {
            n.messages.push(where_.to_string());
        }
        n.count += 1;
        n.last = now;
    }

    /// One message (a datagram may hold several): count, surface, receipt, keepalive.
    fn handle_message(&mut self, _data: &[u8], msg: Decoded, addr: &Addr, cand: &Addr, now: f64) {
        self.rx_messages += 1;
        let name = if msg.name.is_empty() { "unknown".to_string() } else { msg.name.clone() };
        for note in msg.notes.clone() {
            self.note_soft(&note, now, &name);
        }
        bump(&mut self.rx_by_name, &name);
        if !msg.ok {
            self.bad_datagrams += 1;
        }
        let mut probs = msg.problems.clone();
        if !msg.ok && probs.is_empty() {
            probs = vec!["failed checks".into()];
        }
        for p in probs {
            self.note_problem(&p, now, &name);
        }
        if msg.is_keepalive && msg.ok {
            if self.locked.is_none() {
                self.auto_lock(cand, addr);
                self.peer_seen = Some(addr.clone());
            }
            self.on_keepalive(cand, &msg, now);
        }
        let owes = self.protocol.as_ref().and_then(|p| catch_unwind(AssertUnwindSafe(|| p.owes(&msg))).ok().flatten());
        let idx = self.links.iter().position(|(x, _)| x == cand);
        let replies = match (self.protocol.as_mut(), idx) {
            (Some(p), Some(i)) => {
                let link = &mut self.links[i].1;
                catch_unwind(AssertUnwindSafe(|| p.on_receive(link, &msg))).unwrap_or_else(|_| Err("panic".into()))
            }
            _ => Ok(vec![]),
        };
        let replies = match replies {
            Ok(r) => r,
            Err(e) => {
                self.event("error", &format!("protocol on_receive failed for {name}: {e}"), "error", "core");
                vec![]
            }
        };
        let mut answered = false;
        for r in replies {
            answered = self.send(&r, addr, &format!("reply to {name}")) || answered;
        }
        if let Some(what) = owes {
            if answered {
                self.owed_answered += 1;
            } else {
                self.owed.push(Owed { what, name: name.clone(), wall: wall(), mono: now });
            }
        }
        self.emit_tracks(&msg, &name);
    }

    /// Normalized tracks from the protocol's `tracks` hook, to the C2 outputs.
    fn emit_tracks(&mut self, msg: &Decoded, name: &str) {
        if self.on_tracks.is_none() || !msg.ok {
            return;
        }
        let Some(p) = self.protocol.as_mut() else { return };
        let r = match catch_unwind(AssertUnwindSafe(|| p.tracks(msg))) {
            Ok(None) => return,
            Ok(Some(r)) => r,
            Err(_) => Err("panic".into()),
        };
        let tracks = match r {
            Ok(t) => t,
            Err(e) => {
                self.event("error", &format!("protocol tracks() failed for {name}: {e}"), "error", "core");
                return;
            }
        };
        if !tracks.is_empty() {
            self.tracks_out += tracks.len() as u64;
            let f = self.on_tracks.clone().unwrap();
            if let Err(e) = f(&self.id, tracks) {
                self.event("error", &format!("C2 outputs failed: {e}"), "error", "core");
            }
        }
    }

    // ------------------------------------------------------------------ surfacing
    /// Event the first time a problem appears, then at most once a minute with a count.
    /// Keyed by the problem text; `where_` (the message names it appeared in) is recorded.
    pub fn note_problem(&mut self, text: &str, now: f64, where_: &str) {
        if !self.problems.iter().any(|(k, _)| k == text) {
            if self.problems.len() >= MAX_PROBLEMS {
                let oldest = self.problems.iter().enumerate().min_by(|a, b| a.1 .1.last.total_cmp(&b.1 .1.last)).map(|(i, _)| i).unwrap();
                self.problems.remove(oldest);
            }
            self.problems
                .push((text.to_string(), Problem { count: 0, first: now, last: now, last_log: None, logged_count: 0, messages: vec![] }));
        }
        let p = &mut self.problems.iter_mut().find(|(k, _)| k == text).unwrap().1;
        if !where_.is_empty() && !p.messages.iter().any(|m| m == where_) {
            p.messages.push(where_.to_string());
        }
        p.count += 1;
        p.last = now;
        if p.last_log.is_none() || now - p.last_log.unwrap() >= REPEAT_LOG_EVERY_S {
            let extra = if p.count == 1 { String::new() } else { format!(" (seen {} times)", p.count) };
            let inn = if p.messages.is_empty() { String::new() } else { format!(" [in {}]", p.messages.join(", ")) };
            p.last_log = Some(now);
            p.logged_count = p.count;
            let msg = format!("{text}{inn}{extra}");
            self.event("problem", &msg, "warn", "core");
        }
    }

    /// (raw number or None, label) of a decoded field. Protocols may keep raw numbers in
    /// `values` and labels in `fields`.
    fn field(msg: &Decoded, key: &str) -> (Option<Value>, String) {
        let label = msg.fields.get(key);
        let raw = match msg.values.get(key) {
            Some(v) => Some(v.clone()),
            None => match label {
                Some(Value::Number(n)) if !n.is_f64() => Some(Value::Number(n.clone())),
                _ => None,
            },
        };
        let l = match label {
            None => String::new(),
            Some(v) => pyfmt::str(v),
        };
        (raw, l)
    }

    fn suggested_action(&self, code: Option<i64>) -> Option<String> {
        let mapping = self.protocol.as_ref().map(|p| p.peer_request_actions()).unwrap_or_default();
        let name = mapping.get(&code?)?.clone();
        self.actions().iter().any(|a| a.name == name).then_some(name)
    }

    pub fn on_peer_keepalive_fields(&mut self, msg: &Decoded, now: f64) {
        let Some(p) = self.protocol.as_ref() else { return };
        let status_fields = p.peer_status_fields();
        let marker = p.sim_marker();
        let id_field = p.peer_id_field().to_string();
        let req_field = p.peer_request_field().map(String::from);
        for key in status_fields {
            let (raw, label) = Self::field(msg, &key);
            if !label.is_empty() || raw.is_some() {
                let v = if label.is_empty() { pyfmt::str(raw.as_ref().unwrap()) } else { label };
                if let Some(x) = self.peer_status.iter_mut().find(|(k, _)| *k == key) {
                    x.1 = v;
                } else {
                    self.peer_status.push((key, v));
                }
            }
        }
        if !self.peer_status.is_empty() {
            self.peer_status_at = Some(now);
        }
        if let Some((mf, _)) = &marker {
            let (urn, _) = Self::field(msg, mf);
            if urn.is_some() {
                self.peer_urn = urn;
            }
        }
        let (rid, rlabel) = Self::field(msg, &id_field);
        self.peer_device_id = rid.or_else(|| (!rlabel.is_empty()).then(|| json!(rlabel)));
        let Some(req_field) = req_field else { return };
        let (raw, label) = Self::field(msg, &req_field);
        if raw.is_none() && label.is_empty() {
            return;
        }
        let raw_i = raw.as_ref().and_then(Value::as_i64);
        let raw_is_zero = matches!(&raw, Some(Value::Number(n)) if n.as_f64() == Some(0.0)) || raw == Some(Value::Bool(false));
        if raw_is_zero || (raw.is_none() && ["0", "none"].contains(&label.to_lowercase().as_str())) {
            self.peer_request = None;
            return;
        }
        let label = if label.is_empty() { format!("request {}", raw.as_ref().map(pyfmt::str).unwrap_or("None".into())) } else { label };
        if !self.peer_requests.iter().any(|(k, _)| *k == label) {
            self.peer_requests.push((label.clone(), PeerRequest { code: raw_i, count: 0, last: now, last_log: None }));
        }
        let r = &mut self.peer_requests.iter_mut().find(|(k, _)| *k == label).unwrap().1;
        r.count += 1;
        r.last = now;
        let (count, last_log) = (r.count, r.last_log);
        self.peer_request = Some(label.clone());
        if last_log.is_none() || now - last_log.unwrap() >= REPEAT_LOG_EVERY_S {
            let act = self.suggested_action(raw_i);
            let extra = if count == 1 { String::new() } else { format!(" (seen {count} times)") };
            let msg = format!("peer requests: {label}{extra}") + &act.map(|a| format!("; matching action: {a}")).unwrap_or_default();
            self.event("peer", &msg, "warn", "core");
            self.peer_requests.iter_mut().find(|(k, _)| *k == label).unwrap().1.last_log = Some(now);
        }
    }

    /// SIMULATOR if the answering peer is on loopback or marks its keepalives with the
    /// protocol's simulator marker; REAL <device> once any other peer has answered.
    pub fn peer_kind(&self) -> String {
        let addr = self.peer_seen.clone().or_else(|| if self.ka_rx_total > 0 { self.locked.clone() } else { None });
        let Some(addr) = addr else { return self.kind_none.clone() };
        let looped = addr.0.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false);
        let marker = self.protocol.as_ref().and_then(|p| p.sim_marker());
        let is_sim = match (&marker, &self.peer_urn) {
            (Some((_, want)), Some(got)) => json_eq(want, got),
            _ => false,
        };
        if looped || is_sim {
            KIND_SIM.into()
        } else {
            self.kind_real.clone()
        }
    }

    pub fn log_kind(&mut self) {
        let k = self.peer_kind();
        if self.kind_logged.as_ref() != Some(&k) {
            self.kind_logged = Some(k.clone());
            let where_ = self.peer_seen.as_ref().map(fmt_addr).unwrap_or_default();
            let level = if k == self.kind_real { "warn" } else { "info" };
            let msg = format!("peer is {k}") + &if where_.is_empty() { String::new() } else { format!(" at {where_}") };
            self.event("kind", &msg, level, "core");
        }
    }

    fn on_keepalive(&mut self, cand: &Addr, msg: &Decoded, now: f64) {
        self.on_peer_keepalive_fields(msg, now);
        if let Some(c) = msg.peer_tx_counter {
            self.link_mut(cand).rx_counter = c;
        }
        self.last_ka_rx = Some(now);
        self.ka_rx_total += 1;
        self.ka_streak += 1;
        match self.state.as_str() {
            "handshaking" => self.set_state("establishing", "first keepalive from peer"),
            "degraded" => self.set_state("established", "peer keepalive back"),
            "lost" => self.set_state("establishing", "peer keepalive after link lost"),
            _ => {}
        }
        if self.state == "establishing" && self.ka_streak >= self.establish_after {
            let why = format!("{} keepalives received", self.ka_streak);
            self.set_state("established", &why);
        }
        self.log_kind();
    }

    // ------------------------------------------------------------------ actions
    fn all_actions(&self) -> Vec<ActionSpec> {
        self.protocol.as_ref().map(|p| catch_unwind(AssertUnwindSafe(|| p.actions())).unwrap_or_default()).unwrap_or_default()
    }

    fn is_transmit(&self, name: &str, spec: Option<&ActionSpec>) -> bool {
        let gated = self.protocol.as_ref().map(|p| p.transmit_actions()).unwrap_or_default();
        gated.iter().any(|g| g == name) || spec.map(|s| s.dangerous).unwrap_or(false)
    }

    /// The actions offered. Transmit actions vanish unless features.transmit_control.
    pub fn actions(&self) -> Vec<ActionSpec> {
        let acts = self.all_actions();
        if self.cfg.transmit_feature {
            return acts;
        }
        acts.into_iter().filter(|s| !self.is_transmit(&s.name, Some(s))).collect()
    }

    fn effect(&self, spec: &ActionSpec, args: Option<&Map<String, Value>>) -> String {
        let text = if spec.effect.is_empty() { format!("{} will be sent to the {}", spec.label, self.noun) } else { spec.effect.clone() };
        let mut vals: Vec<(String, Value)> = vec![("device_id".into(), json!(self.device_id))];
        for (pname, _, default) in &spec.params {
            if !vals.iter().any(|(k, _)| k == pname) {
                let v = args.and_then(|a| a.get(pname).cloned()).or_else(|| default.clone()).unwrap_or(json!("?"));
                vals.push((pname.clone(), v));
            }
        }
        if let Some(a) = args {
            for (k, v) in a {
                vals.push((k.clone(), v.clone()));
            }
        }
        format_named(&text, &vals)
    }

    /// Every arm / fire / cancel / timeout: an event and a traffic-log entry.
    fn ctl(&mut self, what: &str, name: &str, source: &str, who: &str, extra: &str) {
        let msg = format!("{what} {name} by {source}")
            + &if who.is_empty() { String::new() } else { format!(" ({who})") }
            + &if extra.is_empty() { String::new() } else { format!(": {extra}") };
        self.event(what, &msg, "warn", source);
        self.traffic_seq += 1;
        let e = json!({
            "seq": self.traffic_seq, "time": now_iso(), "ts": wall(), "direction": "ctl",
            "peer": if who.is_empty() { source } else { who }, "length": 0,
            "name": format!("{what} {name}"), "ok": true, "problems": [],
            "fields": {"action": name, "what": what, "source": source, "who": who, "detail": extra},
            "hex": "",
        });
        self.push_traffic(e.as_object().unwrap().clone());
    }

    fn dangerous_spec(&mut self, name: &str, source: &str) -> Result<ActionSpec, ActionError> {
        if !self.cfg.transmit_feature {
            let all = self.all_actions();
            let spec = all.iter().find(|a| a.name == name);
            if self.is_transmit(name, spec) {
                self.event("refused", &format!("{name} refused: {FEATURE_OFF_MSG}"), "warn", source);
                return Err(ActionError::Refused(FEATURE_OFF_MSG.into()));
            }
        }
        let acts = self.actions();
        let Some(spec) = acts.iter().find(|a| a.name == name).cloned() else {
            let known = acts.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", ");
            return Err(ActionError::Unknown(format!(
                "no action named {}. Known: {}",
                pyfmt::str_repr(name),
                if known.is_empty() { "none".into() } else { known }
            )));
        };
        if spec.dangerous && !self.cfg.allow_transmit_control {
            self.event("refused", &format!("{name} refused: allow_transmit_control is false in this session's config"), "warn", source);
            return Err(ActionError::Refused(format!(
                "{name} commands the {} and this session does not allow it. Set allow_transmit_control = true under [sessions.{}] and restart.",
                self.noun, self.id
            )));
        }
        Ok(spec)
    }

    /// Unlock one dangerous action for the arm window (one shot).
    pub fn arm(&mut self, name: &str, source: &str, who: &str, args: &Map<String, Value>) -> Result<Value, ActionError> {
        let spec = self.dangerous_spec(name, source)?;
        if !spec.dangerous {
            return Err(ActionError::Failed(format!("{name} needs no arming")));
        }
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| ActionError::Failed(e.to_string()))?;
        let token = traffic::hex(&b);
        self.arms.retain(|(n, _)| n != name);
        self.arms
            .push((name.into(), Arm { token: token.clone(), until: mono() + self.arm_window_s, source: source.into(), who: who.into() }));
        let effect = self.effect(&spec, Some(args));
        let extra = format!("{} s window; would: {effect}", pyfmt::g(self.arm_window_s));
        self.ctl("arm", name, source, who, &extra);
        Ok(json!({"ok": true, "action": name, "token": token, "expires_in_s": self.arm_window_s,
                  "effect": effect, "device_id": self.device_id, "device_noun": self.noun}))
    }

    pub fn disarm(&mut self, name: &str, source: &str, who: &str) -> Value {
        if let Some(i) = self.arms.iter().position(|(n, _)| n == name) {
            self.arms.remove(i);
            self.ctl("cancel", name, source, who, "");
        }
        json!({"ok": true, "action": name, "armed": false})
    }

    fn expire_arms(&mut self, now: f64) {
        let expired: Vec<(String, Arm)> = self.arms.iter().filter(|(_, a)| now >= a.until).cloned().collect();
        for (name, a) in expired {
            self.arms.retain(|(n, _)| *n != name);
            self.ctl("timeout", &name, &a.source, &a.who, "re-locked");
        }
    }

    pub fn run_action(
        &mut self,
        name: &str,
        confirm: &Value,
        source: &str,
        args: &Map<String, Value>,
        token: Option<&str>,
        who: &str,
    ) -> Result<Value, ActionError> {
        let spec = self.dangerous_spec(name, source)?;
        if spec.dangerous {
            // one shot: any attempt re-locks
            let arm = self.arms.iter().position(|(n, _)| n == name).map(|i| self.arms.remove(i).1);
            let arm = match arm {
                Some(a) if mono() < a.until => a,
                _ => {
                    self.event("refused", &format!("{name} refused: not armed"), "warn", source);
                    return Err(ActionError::Refused(format!(
                        "{name} is locked. Arm it first (CLI: --arm; web page: Arm), then confirm with the {} ID within {} s. Would: {}",
                        self.noun,
                        pyfmt::g(self.arm_window_s),
                        self.effect(&spec, Some(args))
                    )));
                }
            };
            if token != Some(arm.token.as_str()) {
                self.ctl("cancel", name, source, who, "arm token does not match");
                return Err(ActionError::Refused(format!("{name}: this arm belongs to another request; arm again")));
            }
            let typed = pyfmt::str(confirm).trim().to_string();
            if typed != self.device_id.to_string() {
                let d = format!("{} ID typed {}, expected {}", self.noun, pyfmt::str_repr(&pyfmt::str(confirm)), self.device_id);
                self.ctl("cancel", name, source, who, &d);
                return Err(ActionError::Refused(format!(
                    "{name} refused: the {} ID typed does not match ({}). Re-locked; arm again.",
                    self.noun, self.device_id
                )));
            }
        }
        if !self.enabled || self.sock.is_none() {
            return Err(ActionError::Failed(format!("session {} is not running; enable it first", self.id)));
        }
        let mut sent: Vec<String> = vec![];
        let mut size = 0usize;
        for c in self.targets() {
            let idx = self.links.iter().position(|(x, _)| *x == c);
            let built = match (self.protocol.as_mut(), idx) {
                (Some(p), Some(i)) => {
                    let link = &mut self.links[i].1;
                    catch_unwind(AssertUnwindSafe(|| p.build_action(link, name, args))).unwrap_or_else(|_| Err("panic".into()))
                }
                _ => Err("protocol not loaded".into()),
            };
            let data = built.map_err(|e| ActionError::Failed(format!("{name}: {e}")))?;
            for d in data {
                if self.send(&d, &c, &format!("action {name}")) {
                    size += d.len();
                    let t = fmt_addr(&c);
                    if !sent.contains(&t) {
                        sent.push(t);
                    }
                }
            }
        }
        let effect = if spec.dangerous { self.effect(&spec, Some(args)) } else { String::new() };
        if spec.dangerous {
            let to = if sent.is_empty() { "nobody".to_string() } else { sent.join(", ") };
            self.ctl("fire", name, source, who, &format!("{effect}; sent to {to}"));
        }
        let msg = if sent.is_empty() {
            format!("{name} could not be sent")
        } else {
            format!("{name} sent to {} ({size} bytes)", sent.join(", "))
        };
        self.event("action", &msg, if spec.dangerous { "warn" } else { "info" }, source);
        if sent.is_empty() {
            return Err(ActionError::Failed(format!("sending {name} failed; see events")));
        }
        Ok(json!({"ok": true, "session": self.id, "action": name, "bytes": size,
                  "sent_to": sent, "tx_counter": self.link().tx_counter, "effect": effect}))
    }

    // ------------------------------------------------------------------ status
    pub fn status(&mut self, events: usize) -> Value {
        let now = mono();
        let acts: Vec<Value> = self
            .actions()
            .iter()
            .map(|spec| {
                let allowed = !spec.dangerous || self.cfg.allow_transmit_control;
                let arm = find(&self.arms, &spec.name);
                json!({
                    "name": spec.name, "label": spec.label, "dangerous": spec.dangerous,
                    "description": spec.description, "allowed": allowed,
                    "effect": if spec.dangerous { self.effect(spec, None) } else { String::new() },
                    "params": spec.params.iter().map(|p| json!({"name": p.0, "help": p.1, "default": p.2.clone().unwrap_or(Value::Null)})).collect::<Vec<_>>(),
                    "armed_s": match arm { Some(a) if a.until > now => json!(pyfmt::round(a.until - now, 1)), _ => json!(0) },
                    "why_not": if allowed { "" } else { "allow_transmit_control is false in this session's config" },
                })
            })
            .collect();
        let pstat = match self.protocol.as_mut().map(|p| catch_unwind(AssertUnwindSafe(|| p.status()))) {
            None | Some(Ok(None)) => Value::Null,
            Some(Ok(Some(Ok(v)))) => v,
            Some(Ok(Some(Err(e)))) => json!({"error": e}),
            Some(Err(_)) => json!({"error": "panic"}),
        };
        let link = self.link();
        let peer_kind = self.peer_kind();
        let mut notes: Vec<Value> = self
            .notes
            .iter()
            .map(|(k, v)| json!({"note": k, "count": v.count, "messages": v.messages, "last_seen_age_s": age(now, Some(v.last))}))
            .collect();
        notes.sort_by(|a, b| a["last_seen_age_s"].as_f64().unwrap_or(0.0).total_cmp(&b["last_seen_age_s"].as_f64().unwrap_or(0.0)));
        let mut problems: Vec<Value> = self
            .problems
            .iter()
            .map(|(k, v)| {
                json!({"problem": k, "count": v.count, "messages": v.messages,
                       "last_seen_age_s": age(now, Some(v.last)), "first_seen_age_s": age(now, Some(v.first))})
            })
            .collect();
        problems.sort_by(|a, b| a["last_seen_age_s"].as_f64().unwrap_or(0.0).total_cmp(&b["last_seen_age_s"].as_f64().unwrap_or(0.0)));
        let mut fwd_targets = Map::new();
        for (f, st) in &self.fwd_state {
            fwd_targets.insert(
                fmt_addr(f),
                json!({"errors": st.errors, "last_error": st.last_error,
                       "refusing_for_s": st.refused_since.map(|s| json!(pyfmt::round(now - s, 1))).unwrap_or(Value::Null),
                       "last_ok_age_s": age(now, st.last_ok)}),
            );
        }
        let peer_status = if self.peer_status.is_empty() {
            Value::Null
        } else {
            let mut m: Map<String, Value> = self.peer_status.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            m.insert("age_s".into(), age(now, self.peer_status_at));
            Value::Object(m)
        };
        let by_name = |v: &Vec<(String, u64)>| -> Value { Value::Object(v.iter().map(|(k, n)| (k.clone(), json!(n))).collect()) };
        let mut out = json!({
            "id": self.id, "protocol": self.cfg.protocol, "state": self.state,
            "state_age_s": age(now, Some(self.state_since)), "enabled": self.enabled,
            "error": self.error, "local": fmt_addr(&self.local),
            "peer": self.peer().map(|p| fmt_addr(&p)).unwrap_or_default(),
            "locked": self.locked.as_ref().map(fmt_addr), "lock_forced": self.forced,
            "candidates": self.candidates.iter().map(|c| {
                let l = find(&self.links, c).cloned().unwrap_or_default();
                json!({"address": fmt_addr(c), "locked": self.locked.as_ref() == Some(c),
                       "probing": self.locked.is_none() || self.locked.as_ref() == Some(c),
                       "tx_counter": l.tx_counter, "rx_counter": l.rx_counter})
            }).collect::<Vec<_>>(),
            "peer_seen": self.peer_seen.as_ref().map(fmt_addr),
            "forward": self.cfg.forward,
            "allow_transmit_control": self.cfg.allow_transmit_control,
            "transmit_control_feature": self.cfg.transmit_feature,
            "peer_kind": peer_kind,
            "peer_is_real": peer_kind == self.kind_real,
            "device_noun": self.noun,
            "tracks_out": self.tracks_out,
            "protocol_status": pstat,
            "owed_replies": {"waiting": self.owed.len(), "answered": self.owed_answered, "missed": self.owed_missed},
            "local_seen_as": self.local_seen_as(),
            "peer_device_id": self.peer_device_id.clone().unwrap_or(Value::Null),
            "peer_sim_marker": self.peer_urn.clone().unwrap_or(Value::Null),
            "keepalive_interval_s": self.interval, "establish_after": self.establish_after,
            "device_id": self.device_id,
            "tx_counter": link.tx_counter, "rx_counter": link.rx_counter,
            "keepalives_rx": self.ka_rx_total, "keepalive_streak": self.ka_streak,
            "rx_datagrams": self.rx_datagrams, "tx_datagrams": self.tx_datagrams,
            "rx_messages": self.rx_messages,
            "multi_message_datagrams": self.multi_message_datagrams,
            "forward_mode": self.cfg.forward_mode,
            "notes": notes,
            "rx_bytes": self.rx_bytes, "tx_bytes": self.tx_bytes,
            "bad_datagrams": self.bad_datagrams, "foreign_datagrams": self.foreign_datagrams,
            "forwarded": self.forwarded, "forward_errors": self.forward_errors,
            "forward_socket_replaced": self.fwd_sock_replaced,
            "forward_targets": fwd_targets,
            "send_errors": self.send_errors,
            "last_rx_age_s": age(now, self.last_rx), "last_tx_age_s": age(now, self.last_tx),
            "last_keepalive_rx_age_s": age(now, self.last_ka_rx),
            "rx_by_name": by_name(&self.rx_by_name), "tx_by_name": by_name(&self.tx_by_name),
            "actions": acts,
            "problems": problems,
            "peer_request": self.peer_request_status(now),
            "peer_status": peer_status,
        });
        if events > 0 {
            let skip = self.events.len().saturating_sub(events);
            out["events"] = Value::Array(self.events.iter().skip(skip).cloned().map(Value::Object).collect());
        }
        out
    }

    fn peer_request_status(&self, now: f64) -> Value {
        let Some(label) = &self.peer_request else { return Value::Null };
        let r = find(&self.peer_requests, label).unwrap();
        let mapping = self.protocol.as_ref().map(|p| p.peer_request_actions()).unwrap_or_default();
        let wanted = r.code.and_then(|c| mapping.get(&c).cloned());
        let all = self.all_actions();
        let disabled = match &wanted {
            Some(w) if !self.cfg.transmit_feature && self.is_transmit(w, all.iter().find(|a| a.name == *w)) => {
                "transmit control is disabled on this node"
            }
            _ => "",
        };
        json!({"label": label, "code": r.code, "count": r.count,
               "last_seen_age_s": age(now, Some(r.last)),
               "suggested_action": self.suggested_action(r.code), "disabled_reason": disabled})
    }

    /// The address the sensor sees for us: the bound address, or (bound to 0.0.0.0) the source
    /// address the kernel picks toward the peer. A connected UDP socket sends nothing.
    pub fn local_seen_as(&self) -> String {
        let (host, port) = &self.local;
        if !["0.0.0.0", "", "::"].contains(&host.as_str()) {
            return format!("{host}:{port}");
        }
        let probe = || -> io::Result<String> {
            let s = UdpSocket::bind("0.0.0.0:0")?;
            s.connect(resolve(&self.peer().unwrap_or(("0.0.0.0".into(), 0)))?)?;
            Ok(s.local_addr()?.ip().to_string())
        };
        match probe() {
            Ok(ip) => format!("{ip}:{port}"),
            Err(_) => format!("{host}:{port}"),
        }
    }
}

/// Equality of two decoded values, numbers compared by value (1 == 1.0, as in Python).
pub fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Bool(x), Value::Number(y)) | (Value::Number(y), Value::Bool(x)) => y.as_f64() == Some(*x as i64 as f64),
        _ => a == b,
    }
}
