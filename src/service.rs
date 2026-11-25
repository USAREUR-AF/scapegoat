// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The scapegoat daemon: sessions and the scheduler thread.

use crate::clock::{iso_s, wall};
use crate::config::Config;
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
    threads: Mutex<Vec<JoinHandle<()>>>,
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
        Ok(Arc::new(Service {
            config: RwLock::new(config),
            started: wall(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            events: Mutex::new(VecDeque::new()),
            sessions,
            threads: Mutex::new(vec![]),
        }))
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

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
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
