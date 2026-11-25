// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The scapegoat daemon: sessions, the scheduler thread, the HTTP API, island publish.

use crate::clock::{iso_s, mono, wall};
use crate::config::Config;
use crate::outputs::OutputLayer;
use crate::session::Session;
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

/// Shared by the scheduler, the HTTP threads and the island publisher.
pub struct Service {
    pub config: RwLock<Config>,
    pub started: f64,
    pub stop_flag: Arc<AtomicBool>,
    /// Service-level audit (net actions, wire captures, refusals).
    pub events: Mutex<VecDeque<Map<String, Value>>>,
    pub sessions: Vec<Session>,
    pub outputs: Arc<OutputLayer>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    pub httpd: Mutex<Option<crate::http::Server>>,
    /// The machine the network tools read and change (tests answer for it). None: the
    /// network tools are off, and their routes answer 501.
    pub net_host: RwLock<Option<Arc<dyn crate::net::Host>>>,
}

pub const ISLAND_EVERY_S: f64 = 5.0;
pub const ISLAND_ERROR_LOG_EVERY_S: f64 = 60.0;

/// Why a network tool did not run.
#[derive(Debug)]
pub enum NetError {
    /// The network tools (or one of their functions) are not in this build (HTTP 501).
    Unavailable(String),
    /// The node refused it (HTTP 403).
    Permission(String),
    /// A bad argument; nothing was run (HTTP 400).
    Invalid(String),
}

impl Service {
    /// Sessions for every configured session (or only `only_session`), unless given.
    pub fn new(config: Config, sessions: Option<Vec<Session>>, only_session: Option<&str>) -> Result<Arc<Service>, String> {
        if let Some(only) = only_session {
            if config.session(only).is_none() {
                let known: Vec<String> = config.sessions.iter().map(|s| s.id.clone()).collect();
                return Err(format!(
                    "no session named {} in the config. Known: {}",
                    crate::pyfmt::str_repr(only),
                    if known.is_empty() { "none".into() } else { known.join(", ") }
                ));
            }
        }
        let sessions = sessions.unwrap_or_else(|| {
            config.sessions.iter().filter(|sc| only_session.is_none_or(|o| sc.id == o)).map(|sc| Session::new(sc.clone(), None)).collect()
        });
        let outputs = Arc::new(OutputLayer::new(&config.outputs, &config.island_rest, &config.transformers_path));
        for s in &sessions {
            let o = outputs.clone();
            s.set_on_tracks(Arc::new(move |sid: &str, tracks| o.publish(sid, tracks)));
        }
        let svc = Arc::new(Service {
            config: RwLock::new(config),
            started: wall(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            events: Mutex::new(VecDeque::new()),
            sessions,
            outputs,
            threads: Mutex::new(vec![]),
            httpd: Mutex::new(None),
            net_host: RwLock::new(Some(Arc::new(crate::net::RealHost))),
        });
        svc.warn_double_publish();
        Ok(svc)
    }

    /// One track path per sensor: a session whose messages are forwarded to a receiver that
    /// publishes tracks (e.g. a Billie kid) must not also feed an output that publishes the
    /// same tracks.
    fn warn_double_publish(&self) {
        for (name, enabled, wanted) in self.outputs.wants() {
            if !enabled {
                continue;
            }
            for s in &self.sessions {
                let fwd = s.with(|i| i.cfg.forward.clone());
                if (wanted.is_empty() || wanted.contains(&s.id)) && !fwd.is_empty() {
                    self.event(
                        "outputs",
                        &format!(
                            "session {} forwards to {} and feeds output {name}: make sure the forward receiver does not also publish these tracks (one track path per sensor)",
                            s.id,
                            fwd.join(", ")
                        ),
                        "warn",
                        "core",
                    );
                }
            }
        }
    }

    pub fn session(&self, id: &str) -> Option<&Session> {
        self.sessions.iter().find(|s| s.id == id)
    }

    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.iter().map(|s| s.id.clone()).collect()
    }

    pub fn cfg(&self) -> std::sync::RwLockReadGuard<'_, Config> {
        self.config.read().unwrap_or_else(|e| e.into_inner())
    }

    // -------------------------------------------------------------- audit
    pub fn event(&self, kind: &str, msg: &str, level: &str, source: &str) {
        let ts = wall();
        let ev = json!({"time": iso_s(ts), "ts": ts, "kind": kind, "level": level, "source": source, "message": msg});
        let mut ev_q = self.events.lock().unwrap_or_else(|e| e.into_inner());
        if ev_q.len() == 500 {
            ev_q.pop_front();
        }
        ev_q.push_back(ev.as_object().unwrap().clone());
        crate::log::info("scapegoat.service", &format!("[service] {kind} ({source}): {msg}"));
    }

    pub fn events_list(&self) -> Vec<Value> {
        self.events.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().map(Value::Object).collect()
    }

    pub fn add_thread(&self, t: JoinHandle<()>) {
        self.threads.lock().unwrap_or_else(|e| e.into_inner()).push(t);
    }

    // -------------------------------------------------------------- run
    /// Open the sessions and start the scheduler.
    pub fn start_sessions(self: &Arc<Self>) {
        for s in &self.sessions {
            s.start();
        }
        let me = self.clone();
        let t = std::thread::Builder::new().name("scapegoat-scheduler".into()).spawn(move || me.scheduler()).expect("scheduler thread");
        self.add_thread(t);
    }

    /// Everything: sessions, scheduler, island publish, outputs, and the HTTP API if asked.
    pub fn start(self: &Arc<Self>, http: bool) -> std::io::Result<()> {
        self.start_sessions();
        if !self.cfg().island_rest.is_empty() {
            let me = self.clone();
            let t = std::thread::Builder::new().name("scapegoat-island".into()).spawn(move || me.island()).expect("island thread");
            self.add_thread(t);
        }
        self.outputs.start();
        if http {
            let bind = self.cfg().bind.clone();
            let server = crate::api::serve(self.clone(), &bind)?;
            crate::log::info("scapegoat.service", &format!("scapegoat {} API and web page on http://{}/", crate::VERSION, server.addr));
            *self.httpd.lock().unwrap_or_else(|e| e.into_inner()) = Some(server);
        }
        Ok(())
    }

    /// The address the HTTP API listens on.
    pub fn http_addr(&self) -> Option<std::net::SocketAddr> {
        self.httpd.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|s| s.addr)
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        self.outputs.stop();
        if let Some(mut h) = self.httpd.lock().unwrap_or_else(|e| e.into_inner()).take() {
            h.stop();
        }
        for s in &self.sessions {
            s.stop();
        }
        let threads: Vec<JoinHandle<()>> = self.threads.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect();
        for t in threads {
            let _ = t.join();
        }
    }

    fn scheduler(&self) {
        let intervals: Vec<f64> = self.sessions.iter().map(|s| s.interval()).filter(|i| *i > 0.0).collect();
        let min = intervals.iter().cloned().fold(f64::INFINITY, f64::min);
        let min = if min.is_finite() { min } else { 1.0 };
        let step = (min / 20.0).clamp(0.01, 0.5);
        loop {
            std::thread::sleep(Duration::from_secs_f64(step));
            if self.stop_flag.load(Ordering::SeqCst) {
                return;
            }
            for s in &self.sessions {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| s.tick(None)));
                if r.is_err() {
                    crate::log::error("scapegoat.service", &format!("tick failed for {}", s.id));
                }
            }
        }
    }
}

impl Service {
    // -------------------------------------------------------------- island publish
    fn island(&self) {
        let mut last_err_log = 0.0;
        loop {
            let end = mono() + ISLAND_EVERY_S;
            while mono() < end {
                if self.stop_flag.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let node = self.cfg().node_name.clone();
            for s in &self.sessions {
                let mut st = s.status(0);
                st["node"] = json!(node);
                st["time"] = json!(wall());
                let body = crate::pyfmt::dumps(&st);
                for url in self.island_urls(&s.id) {
                    let r = crate::http::request(
                        "PUT",
                        &url,
                        &[("Content-Type", "application/json")],
                        Some(body.as_bytes()),
                        Duration::from_secs(3),
                    );
                    let failed = match r {
                        Ok(resp) if resp.status < 400 => None,
                        Ok(resp) => Some(format!("HTTP Error {}: {}", resp.status, crate::http::reason(resp.status))),
                        Err(e) => Some(format!("<urlopen error {}>", e.0)),
                    };
                    if let Some(exc) = failed {
                        let now = mono();
                        if now - last_err_log > ISLAND_ERROR_LOG_EVERY_S {
                            last_err_log = now;
                            self.event("island", &format!("publish to {url} failed: {exc} (logged at most once a minute)"), "warn", "core");
                        }
                    }
                }
            }
        }
    }

    /// scapegoat/<node>/<session>/status.
    pub fn island_urls(&self, sid: &str) -> Vec<String> {
        let c = self.cfg();
        let base = c.island_rest.trim_end_matches('/');
        vec![format!("{base}/scapegoat/{}/{sid}/status", c.node_name)]
    }

    // -------------------------------------------------------------- API helpers
    pub fn health(&self) -> Value {
        let c = self.cfg().clone();
        json!({"ok": true, "version": crate::VERSION, "node_name": c.node_name,
               "uptime_s": crate::pyfmt::round(wall() - self.started, 1),
               "sessions": self.sessions.len(),
               "profile": if c.profile.is_empty() { Value::Null } else { json!(c.profile) },
               "config_path": c.path,
               "allow_net_control": c.allow_net_control,
               "expected_local": crate::node::check_expected(&c.expected_local_address),
               "topology": if c.topology.is_empty() { "auto".to_string() } else { c.topology.clone() },
               "identity": self.identity(),
               "outputs": self.outputs.status()})
    }

    /// Which machine this is, for the first line of every page and of `scapegoat status`.
    pub fn identity(&self) -> Value {
        let c = self.cfg().clone();
        let n = crate::node::snapshot(&c, false);
        let b = n.get("billie").cloned().unwrap_or(Value::Null);
        let role = c.node_role.clone();
        let handle = b.get("node_handle").cloned().unwrap_or(Value::Null);
        let mesh = n["addresses"].as_array().and_then(|a| {
            a.iter()
                .find(|x| x["role"] == "NetBird mesh" && x["family"] == "ipv4")
                .map(|x| json!(x["cidr"].as_str().unwrap_or("").split('/').next().unwrap_or("")))
        });
        let slot = b.get("billie_fabric_prefix").cloned().unwrap_or(Value::Null);
        let slot_s = if slot.is_null() { String::new() } else { crate::pyfmt::str(&slot) };
        let slot_short = if slot.is_null() || slot_s.is_empty() || slot_s.chars().count() <= 24 {
            slot.clone()
        } else {
            let ch: Vec<char> = slot_s.chars().collect();
            json!(format!("{}…{}", ch[..10].iter().collect::<String>(), ch[ch.len() - 10..].iter().collect::<String>()))
        };
        let host = n["hostname"].as_str().unwrap_or("?").to_string();
        let title = format!(
            "{host} · {}",
            if !role.is_empty() {
                role.clone()
            } else if crate::config::truthy(Some(&handle)) {
                crate::pyfmt::str(&handle)
            } else {
                "role not set".into()
            }
        );
        json!({"hostname": n["hostname"], "node_role": if role.is_empty() { Value::Null } else { json!(role) },
               "role_note": if role.is_empty() { "role not set (node_role in scapegoat.toml)" } else { "" },
               "billie_node": handle, "mesh_address": mesh.unwrap_or(Value::Null), "slot": slot,
               "slot_short": slot_short, "title": title,
               "sensor_sees": self.sessions.iter().map(|s| json!({"session": s.id, "address": s.local_seen_as()})).collect::<Vec<_>>()})
    }

    fn host(&self) -> Result<Arc<dyn crate::net::Host>, NetError> {
        self.net_host
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| NetError::Unavailable("network tools are not installed (scapegoat net is off in this service)".into()))
    }

    pub fn net_snapshot(&self) -> Result<Value, NetError> {
        let raw = Value::Object(self.cfg().raw.clone());
        Ok(crate::net::snapshot(self.host()?.as_ref(), &raw))
    }

    /// A read-only probe: ping, capture, udp_probe.
    pub fn net_probe(&self, name: &str, args: &Map<String, Value>) -> Result<Value, NetError> {
        crate::net::probe(self.host()?.as_ref(), name, args).map_err(NetError::Invalid)
    }

    /// A guarded control; the caller has checked allow_net_control and confirm.
    pub fn net_run(&self, name: &str, args: &Map<String, Value>, source: &str) -> Result<Value, NetError> {
        let host = self.host()?;
        self.event("net", &format!("net {name} {}", crate::pyfmt::dumps_sorted(&Value::Object(args.clone()))), "info", source);
        let raw = Value::Object(self.cfg().raw.clone());
        let result = crate::net::run(host.as_ref(), name, args, &raw);
        let shown = crate::pyfmt::head(&crate::pyfmt::dumps(&result), 400);
        self.event("net", &format!("net {name} result: {shown}"), "info", source);
        Ok(result)
    }
}

/// Start everything and block until SIGTERM / Ctrl-C.
pub fn run_forever(config: Config, only_session: Option<&str>) -> Result<i32, String> {
    let bind = config.bind.clone();
    let svc = Service::new(config, None, only_session)?;
    crate::signals::install();
    if let Err(e) = svc.start(true) {
        svc.stop();
        return Err(format!("cannot start the API on {bind}: {}", crate::pyfmt::os_error(&e)));
    }
    while !crate::signals::stopped() {
        std::thread::sleep(Duration::from_millis(200));
    }
    crate::log::info("scapegoat.service", "stopping");
    svc.stop();
    Ok(0)
}
