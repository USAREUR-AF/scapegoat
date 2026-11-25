// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! A tiny fake protocol and fake sensor for core tests (the Rust form of tests/fakeproto.py
//! and tests/helpers.py).
//!
//! Wire format: b"KA" + tx(2) + rx(2) + action(1) + sum(1)  -> keepalive
//!              b"DT" + payload                              -> data (no reply)

use scapegoat::config::{self, Config};
use scapegoat::protocol::{ActionSpec, Decoded, HookResult, LinkState, Protocol};
use scapegoat::service::Service;
use scapegoat::session::Session;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn ka(tx: u16, rx: u16, action: u8) -> Vec<u8> {
    let mut b = b"KA".to_vec();
    b.extend_from_slice(&tx.to_be_bytes());
    b.extend_from_slice(&rx.to_be_bytes());
    b.push(action);
    let s = b.iter().map(|x| *x as u32).sum::<u32>() % 256;
    b.push(s as u8);
    b
}

#[derive(Clone, Default)]
pub struct FakeProtocol {
    pub noun: Option<(String, String, String)>,
    /// Owes an answer to every Data message and never gives one (OwingProto).
    pub owes_data: bool,
    /// Replace the action list (test_peer_request_and_status).
    pub actions_override: Option<Vec<ActionSpec>>,
}

impl Protocol for FakeProtocol {
    fn name(&self) -> &str {
        "fake"
    }
    fn keepalive_interval_s(&self) -> f64 {
        0.2
    }
    fn keepalive(&mut self, link: &mut LinkState, action: i64) -> HookResult<Vec<u8>> {
        let tx = link.next_tx() as u16;
        Ok(ka(tx, link.rx_counter as u16, action as u8))
    }
    fn decode(&mut self, d: &[u8]) -> Decoded {
        if d.len() == 8 && &d[..2] == b"KA" {
            let tx = u16::from_be_bytes([d[2], d[3]]) as i64;
            let rx = u16::from_be_bytes([d[4], d[5]]) as i64;
            let ok = d[..7].iter().map(|x| *x as u32).sum::<u32>() % 256 == d[7] as u32;
            let f = json!({"tx": tx, "rx": rx, "action": d[6]});
            return Decoded::new(
                "KeepAlive",
                f.as_object().unwrap().clone(),
                ok,
                if ok { vec![] } else { vec!["bad checksum".into()] },
                true,
                Some(tx),
            );
        }
        if d.len() >= 2 && &d[..2] == b"DT" {
            let f = json!({"payload": scapegoat::traffic::hex(&d[2..])});
            return Decoded::new("Data", f.as_object().unwrap().clone(), true, vec![], false, None);
        }
        Decoded::new("unknown", Map::new(), false, vec!["unknown message".into()], false, None)
    }
    fn on_receive(&mut self, link: &mut LinkState, msg: &Decoded) -> HookResult<Vec<Vec<u8>>> {
        if msg.is_keepalive && msg.fields.get("action").and_then(Value::as_i64) == Some(1) {
            return Ok(vec![self.keepalive(link, 0)?]);
        }
        Ok(vec![])
    }
    fn actions(&self) -> Vec<ActionSpec> {
        if let Some(a) = &self.actions_override {
            return a.clone();
        }
        vec![
            ActionSpec::new("ping", "Ping", false, "KA"),
            ActionSpec::new("ask_reply", "Ask for a reply", false, "KA 1"),
            ActionSpec::new("transmit_on", "Transmit on", true, "KA 5"),
        ]
    }
    fn build_action(&mut self, link: &mut LinkState, name: &str, _args: &Map<String, Value>) -> HookResult<Vec<Vec<u8>>> {
        let code = match name {
            "ping" => 0,
            "ask_reply" => 1,
            "transmit_on" => 5,
            _ => return Err(format!("'{name}'")),
        };
        Ok(vec![self.keepalive(link, code)?])
    }
    fn owes(&self, msg: &Decoded) -> Option<String> {
        (self.owes_data && msg.name == "Data").then(|| "answer".into())
    }
    fn peer_request_field(&self) -> Option<&str> {
        Some("request")
    }
    fn peer_request_actions(&self) -> BTreeMap<i64, String> {
        BTreeMap::from([(4, "transmit_on".to_string())])
    }
    fn peer_status_fields(&self) -> Vec<String> {
        vec!["sensor_status".into()]
    }
    fn transmit_actions(&self) -> Vec<String> {
        vec!["transmit_on".into(), "transmit_off".into()]
    }
    fn sim_marker(&self) -> Option<(String, Value)> {
        Some(("sim_tag".into(), json!(0xFFFFFF)))
    }
    fn device_noun(&self) -> &str {
        self.noun.as_ref().map(|n| n.0.as_str()).unwrap_or("device")
    }
    fn device_id_setting(&self) -> &str {
        self.noun.as_ref().map(|n| n.1.as_str()).unwrap_or("device_id")
    }
    fn peer_id_field(&self) -> &str {
        self.noun.as_ref().map(|n| n.2.as_str()).unwrap_or("device_id")
    }
}

pub fn fake() -> Option<Box<dyn Protocol>> {
    Some(Box::new(FakeProtocol::default()))
}

/// Waits for a keepalive, then answers the sender's address every interval.
pub struct FakeSensor {
    pub port: u16,
    pub silent: Arc<AtomicBool>,
    pub peer: Arc<Mutex<Option<SocketAddr>>>,
    pub received: Arc<Mutex<Vec<Vec<u8>>>>,
    sock: UdpSocket,
    stop: Arc<AtomicBool>,
    t: Option<std::thread::JoinHandle<()>>,
}

impl FakeSensor {
    pub fn start(interval: f64) -> FakeSensor {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let port = sock.local_addr().unwrap().port();
        let (silent, peer, received, stop) =
            (Arc::new(AtomicBool::new(false)), Arc::new(Mutex::new(None)), Arc::new(Mutex::new(vec![])), Arc::new(AtomicBool::new(false)));
        let (s2, si, pe, re, st) = (sock.try_clone().unwrap(), silent.clone(), peer.clone(), received.clone(), stop.clone());
        let t = std::thread::spawn(move || {
            let mut nxt = Instant::now();
            let mut tx: u16 = 0;
            let mut buf = [0u8; 2048];
            while !st.load(Ordering::Relaxed) {
                if let Ok((n, a)) = s2.recv_from(&mut buf) {
                    re.lock().unwrap().push(buf[..n].to_vec());
                    *pe.lock().unwrap() = Some(a);
                }
                let p = *pe.lock().unwrap();
                if let (Some(p), false) = (p, si.load(Ordering::Relaxed)) {
                    if Instant::now() >= nxt {
                        tx = tx.wrapping_add(1);
                        let _ = s2.send_to(&ka(tx, 0, 0), p);
                        nxt = Instant::now() + Duration::from_secs_f64(interval);
                    }
                }
            }
        });
        FakeSensor { port, silent, peer, received, sock, stop, t: Some(t) }
    }

    pub fn send(&self, data: &[u8]) {
        if let Some(p) = *self.peer.lock().unwrap() {
            self.sock.send_to(data, p).unwrap();
        }
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        *self.peer.lock().unwrap()
    }

    pub fn received_len(&self) -> usize {
        self.received.lock().unwrap().len()
    }

    pub fn set_silent(&self, v: bool) {
        self.silent.store(v, Ordering::Relaxed);
    }
}

impl Drop for FakeSensor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.t.take() {
            let _ = t.join();
        }
    }
}

pub fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub struct Opts {
    pub forward: Vec<String>,
    pub allow_transmit: bool,
    pub interval: f64,
    pub allow_net: bool,
    pub candidates: Option<Vec<String>>,
    pub extra: Value,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { forward: vec![], allow_transmit: false, interval: 0.2, allow_net: false, candidates: None, extra: json!({}) }
    }
}

pub fn make_config(sensor_port: u16, local_port: u16, o: Opts) -> Config {
    let mut data = json!({
        "bind": "127.0.0.1:0",
        "allow_net_control": o.allow_net,
        "node_name": "test-node",
        "sessions": {"sensor": {
            "protocol": "fake", "enabled": true,
            "local": format!("127.0.0.1:{local_port}"), "peer": format!("127.0.0.1:{sensor_port}"),
            "forward": o.forward, "allow_transmit_control": o.allow_transmit,
            "protocol_settings": {"keepalive_interval_s": o.interval, "establish_after": 3, "device_id": 1},
        }},
    });
    if let Some(c) = o.candidates {
        data["sessions"]["sensor"]["peer"] = json!("");
        data["sessions"]["sensor"]["peer_candidates"] = json!(c);
    }
    if let Value::Object(x) = o.extra {
        for (k, v) in x {
            data[k] = v;
        }
    }
    config::from_dict(&data, "").unwrap()
}

pub fn wait_for(mut pred: impl FnMut() -> bool, timeout: f64) -> bool {
    let end = Instant::now() + Duration::from_secs_f64(timeout);
    while Instant::now() < end {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// A started service whose sessions run the fake protocol.
pub fn start(cfg: &Config, proto: impl Fn() -> Box<dyn Protocol>) -> (Arc<Service>, Session) {
    let sessions: Vec<Session> = cfg.sessions.iter().map(|sc| Session::new(sc.clone(), Some(proto()))).collect();
    let s = sessions[0].clone();
    let svc = Service::new(cfg.clone(), Some(sessions), None).unwrap();
    svc.start_sessions();
    (svc, s)
}

pub fn events_of(s: &Session, kind: &str) -> Vec<String> {
    s.with(|i| i.events.iter().filter(|e| e["kind"] == kind).map(|e| e["message"].as_str().unwrap().to_string()).collect())
}

pub fn has_event(s: &Session, pred: impl Fn(&Map<String, Value>) -> bool) -> bool {
    s.with(|i| i.events.iter().any(pred))
}

/// Stops the service on drop, so a failed assertion does not leave sockets bound.
pub struct Running(pub Arc<Service>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.stop();
    }
}
