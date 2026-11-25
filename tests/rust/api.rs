// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_api.py and TestLatchCli of tests/test_latch.py: the HTTP API and the CLI
//! against a running service.

use crate::support::*;
use scapegoat::cli::{main_io, Io};
use scapegoat::config::Config;
use scapegoat::service::Service;
use scapegoat::session::Session;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

pub struct Api {
    pub sensor: FakeSensor,
    pub svc: Arc<Service>,
    pub base: String,
}

impl Drop for Api {
    fn drop(&mut self) {
        self.svc.stop();
    }
}

pub fn api_with(sensor: FakeSensor, cfg: Config) -> Api {
    let sessions: Vec<Session> = cfg.sessions.iter().map(|sc| Session::new(sc.clone(), fake())).collect();
    let svc = Service::new(cfg, Some(sessions), None).unwrap();
    svc.start(true).unwrap();
    let base = format!("http://127.0.0.1:{}", svc.http_addr().unwrap().port());
    Api { sensor, svc, base }
}

pub fn api(o: Opts) -> Api {
    let sensor = FakeSensor::start(0.2);
    let cfg = make_config(sensor.port, free_udp_port(), o);
    api_with(sensor, cfg)
}

impl Api {
    pub fn req(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let data = body.map(|b| b.to_string());
        let r = scapegoat::http::request(
            method,
            &format!("{}{path}", self.base),
            &[("Content-Type", "application/json"), ("X-Scapegoat-Source", "ui")],
            data.as_deref().map(str::as_bytes),
            Duration::from_secs(10),
        )
        .unwrap();
        let ctype = r.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_default();
        let v = if ctype.contains("json") {
            serde_json::from_slice(&r.body).unwrap()
        } else {
            Value::String(String::from_utf8_lossy(&r.body).to_string())
        };
        (r.status, v)
    }

    pub fn cli(&self, argv: &[&str]) -> (i32, String, String) {
        let mut a: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        a.extend(["--api".to_string(), self.base.clone()]);
        run_cli(a)
    }

    pub fn session(&self) -> Session {
        self.svc.sessions[0].clone()
    }
}

pub fn run_cli(argv: Vec<String>) -> (i32, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input: &[u8] = b"";
    let code = {
        let mut io = Io { out: &mut out, err: &mut err, input: &mut input };
        main_io(argv, &mut io)
    };
    (code, String::from_utf8_lossy(&out).to_string(), String::from_utf8_lossy(&err).to_string())
}

fn names(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|a| a["name"].as_str().unwrap().to_string()).collect()
}

mod api_tests {
    use super::*;

    #[test]
    fn test_health_and_page() {
        let a = api(Opts::default());
        let (code, body) = a.req("GET", "/api/health", None);
        assert_eq!(code, 200);
        assert_eq!(body["ok"], true);
        assert!(body.get("version").is_some());
        let (code, page) = a.req("GET", "/", None);
        assert_eq!(code, 200);
        assert!(page.as_str().unwrap().contains("scapegoat"));
    }

    #[test]
    fn test_sessions() {
        let a = api(Opts::default());
        let s = a.session();
        assert!(wait_for(|| s.state() == "established", 5.0));
        let (code, lst) = a.req("GET", "/api/sessions", None);
        assert_eq!(code, 200);
        assert_eq!(lst[0]["id"], "sensor");
        assert_eq!(lst[0]["state"], "established");
        let (_, one) = a.req("GET", "/api/sessions/sensor", None);
        assert!(one["events"].as_array().unwrap().len() <= 50);
        let (code, ev) = a.req("GET", "/api/sessions/sensor/events?n=3", None);
        assert_eq!(code, 200);
        assert!(ev.as_array().unwrap().len() <= 3);
        assert_eq!(a.req("GET", "/api/sessions/nope", None).0, 404);
        assert_eq!(a.req("GET", "/api/nothing", None).0, 404);
    }

    #[test]
    fn test_actions() {
        let a = api(Opts::default());
        assert!(wait_for(|| a.session().with(|i| i.sock.is_some()), 2.0));
        let (code, r) = a.req("POST", "/api/sessions/sensor/actions/ping", Some(json!({})));
        assert_eq!(code, 200, "{r}");
        let (code, r) = a.req("POST", "/api/sessions/sensor/actions/transmit_on", Some(json!({"confirm": true})));
        assert_eq!(code, 403);
        assert!(r["error"].as_str().unwrap().contains("features.transmit_control = false"));
        assert_eq!(a.req("POST", "/api/sessions/sensor/actions/bogus", Some(json!({}))).0, 404);
        let ev = a.session().get_events(20);
        assert!(ev.iter().any(|e| e["source"] == "ui" && e["message"].as_str().unwrap().contains("ping")));
    }

    #[test]
    fn test_lifecycle() {
        let a = api(Opts::default());
        let (code, r) = a.req("POST", "/api/sessions/sensor/disable", Some(json!({})));
        assert_eq!((code, r["state"].as_str().unwrap()), (200, "disabled"));
        assert_eq!(a.req("POST", "/api/sessions/sensor/actions/ping", Some(json!({}))).0, 400);
        let (code, r) = a.req("POST", "/api/sessions/sensor/enable", Some(json!({})));
        assert_eq!(code, 200);
        assert_ne!(r["state"], "disabled");
        assert_eq!(a.req("POST", "/api/sessions/sensor/reset", Some(json!({}))).0, 200);
    }

    #[test]
    fn test_net_missing_module_is_clear_error() {
        // Python removes scapegoat.net from sys.modules; here the service has no network host.
        let a = api(Opts::default());
        *a.svc.net_host.write().unwrap() = None;
        let (code, r) = a.req("GET", "/api/net", None);
        assert_eq!(code, 501);
        assert!(r["error"].as_str().unwrap().contains("not installed"));
        assert_eq!(a.req("POST", "/api/net/ping", Some(json!({"ip": "127.0.0.1"}))).0, 501);
    }

    #[test]
    fn test_net_snapshot_and_probe() {
        // Python replaces scapegoat.net with stand-ins; here a fake host answers for the machine.
        let a = api(Opts::default());
        *a.svc.net_host.write().unwrap() = Some(Arc::new(crate::net::FakeHost::default_host()));
        let (code, r) = a.req("GET", "/api/net", None);
        assert_eq!(code, 200);
        assert!(r["interfaces"].as_array().unwrap().iter().any(|i| i["name"] == "lo"));
        let (code, r) = a.req("POST", "/api/net/ping", Some(json!({"ip": "127.0.0.1", "junk": 1})));
        assert_eq!((code, r["ip"].clone()), (200, json!("127.0.0.1")));
    }

    #[test]
    fn test_net_control_refused_when_off() {
        let a = api(Opts::default());
        let (code, r) = a.req("POST", "/api/net/link_down", Some(json!({"iface": "eth0", "confirm": true})));
        assert_eq!(code, 403);
        assert!(r["error"].as_str().unwrap().contains("allow_net_control"));
    }

    #[test]
    fn test_cli() {
        let a = api(Opts::default());
        assert!(wait_for(|| a.session().with(|i| i.sock.is_some()), 2.0));
        let (code, out, _) = a.cli(&["status"]);
        assert_eq!(code, 0);
        assert!(out.contains("sensor"));
        assert!(out.contains("SESSION"));
        let (_, out, _) = a.cli(&["status", "sensor", "--json"]);
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["id"], "sensor");
        let (code, _, err) = a.cli(&["action", "sensor", "transmit_on", "--arm", "--confirm", "1"]);
        assert_eq!(code, 1);
        assert!(err.contains("disabled by feature flag"), "{err}");
        let (code, out, _) = a.cli(&["action", "sensor", "ask_reply"]);
        assert_eq!(code, 0, "{out}");
        let (code, out, _) = a.cli(&["events", "sensor", "-n", "5"]);
        assert_eq!(code, 0);
        assert!(out.contains("cli"));
        let (_, out, _) = a.cli(&["actions", "sensor"]);
        assert!(!out.contains("transmit"));
        let (_, st) = a.req("GET", "/api/sessions/sensor", None);
        assert!(!names(&st["actions"]).contains(&"transmit_on".to_string()));
        let (code, _, _) = a.cli(&["status", "nope"]);
        assert_eq!(code, 1);
    }

    #[test]
    fn test_unreachable_service() {
        let (code, _, err) = run_cli(vec!["status".into(), "--api".into(), format!("http://127.0.0.1:{}", free_udp_port())]);
        assert_eq!(code, 1);
        assert!(err.contains("cannot reach"), "{err}");
    }
}

fn lock_api() -> Api {
    let sensor = FakeSensor::start(0.2);
    let cfg = make_config(
        sensor.port,
        free_udp_port(),
        Opts {
            candidates: Some(vec!["127.0.0.2:9".into(), format!("127.0.0.1:{}", sensor.port)]),
            extra: json!({"expected_local_address": "127.0.0.1/8"}),
            ..Default::default()
        },
    );
    api_with(sensor, cfg)
}

mod lock_and_address {
    use super::*;

    #[test]
    fn test_lock_endpoint_and_cli() {
        let a = lock_api();
        let (code, r) = a.req("POST", "/api/sessions/sensor/lock", Some(json!({"peer": "127.0.0.2:9"})));
        assert_eq!((code, r["locked"].clone(), r["lock_forced"].clone()), (200, json!("127.0.0.2:9"), json!(true)));
        assert_eq!(a.req("POST", "/api/sessions/sensor/lock", Some(json!({}))).0, 400);
        let (code, out, _) = a.cli(&["lock", "sensor", &format!("127.0.0.1:{}", a.sensor.port)]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("locked onto"));
        let (_, out, _) = a.cli(&["status", "sensor"]);
        assert!(out.contains("LOCKED"));
    }

    #[test]
    fn test_expected_address_in_health_and_status() {
        let a = lock_api();
        let (_, h) = a.req("GET", "/api/health", None);
        assert_eq!(h["expected_local"]["present"], true, "{h}");
        let (_, out, _) = a.cli(&["status"]);
        assert!(out.contains("Node address: [OK]"), "{out}");
        assert!((out + " probing").contains("probing"));
    }
}

#[test]
fn test_confirm_required_then_runs() {
    let a = api(Opts { allow_net: true, ..Default::default() });
    let host = Arc::new(crate::net::FakeHost::default_host());
    *a.svc.net_host.write().unwrap() = Some(host.clone());
    let (code, _) = a.req("POST", "/api/net/link_up", Some(json!({"iface": "eth0"})));
    assert_eq!(code, 403);
    assert!(host.calls().is_empty());
    let (code, r) = a.req("POST", "/api/net/link_up", Some(json!({"iface": "eth0", "confirm": true})));
    assert_eq!(code, 200, "{r}");
    assert_eq!(host.calls()[0], ["ip", "link", "set", "dev", "eth0", "up"].map(String::from).to_vec());
    assert!(a.svc.events_list().iter().any(|e| e["source"] == "ui"));
}

#[test]
fn test_profiles_command() {
    let (code, out, _) = run_cli(vec!["profiles".into(), "--profiles-dir".into(), "/nonexistent".into()]);
    assert_eq!(code, 0);
    assert!(out.contains("sim-local"));
    assert!(out.contains("TESTING"));
}

mod traffic_api {
    use super::*;

    #[test]
    fn test_traffic_endpoint_and_watch_once() {
        let a = api(Opts::default());
        let s = a.session();
        assert!(wait_for(|| s.state() == "established", 5.0));
        let (code, r) = a.req("GET", "/api/sessions/sensor/traffic?limit=5", None);
        assert_eq!(code, 200);
        assert!(r["entries"].as_array().unwrap().len() <= 5);
        let last = r["last_seq"].as_i64().unwrap();
        let (_, r2) = a.req("GET", &format!("/api/sessions/sensor/traffic?since={}", last - 2), None);
        assert!(r2["entries"].as_array().unwrap().iter().all(|e| e["seq"].as_i64().unwrap() > last - 2));
        assert_eq!(a.req("GET", "/api/sessions/sensor/traffic?since=x", None).0, 400);
        let (code, out, _) = a.cli(&["watch", "sensor", "--once", "--last", "3"]);
        assert_eq!(code, 0);
        assert!(out.contains("KeepAlive"), "{out}");
        assert!(out.contains("=== *** SIMULATOR - not a real sensor *** ==="));
        let (_, out, _) = a.cli(&["--json", "watch", "sensor", "--once", "--filter", "Keep"]);
        let lines: Vec<Value> = out.lines().filter(|l| l.starts_with('{')).map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(lines[0]["type"], "peer_kind");
        assert!(lines.iter().filter(|x| x.get("seq").is_some()).all(|x| x["name"] == "KeepAlive"));
    }

    #[test]
    fn test_api_option_before_command() {
        let a = api(Opts::default());
        let (code, out, err) = run_cli(vec!["--api".into(), a.base.clone(), "--json".into(), "status".into()]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["sessions"][0]["id"], "sensor");
    }
}

#[test]
fn test_node_endpoint() {
    let a = api(Opts::default());
    let (code, n) = a.req("GET", "/api/node", None);
    assert_eq!(code, 200);
    assert!(n.get("hostname").is_some());
    assert!(n["addresses"].is_array());
    let (_, n2) = a.req("GET", "/api/node?loopback=1", None);
    assert!(n2["addresses"].as_array().unwrap().iter().any(|x| x["role"] == "loopback") || n2.get("error").is_some());
    let (_, out, _) = a.cli(&["status"]);
    assert!(out.contains("This node:"));
}

#[test]
fn test_identity_in_health_and_status() {
    let a = api(Opts::default());
    let (_, h) = a.req("GET", "/api/health", None);
    let ident = &h["identity"];
    assert_eq!(ident["role_note"], "role not set (node_role in scapegoat.toml)");
    assert!(ident["title"].as_str().unwrap().ends_with("role not set") || !ident["billie_node"].is_null());
    assert!(ident["sensor_sees"][0]["address"].as_str().unwrap().starts_with("127.0.0.1:"));
    a.svc.config.write().unwrap().node_role = "C2 node · Pi A".into();
    let (_, h) = a.req("GET", "/api/health", None);
    assert!(h["identity"]["title"].as_str().unwrap().ends_with(" · C2 node · Pi A"));
    let (_, out, _) = a.cli(&["status"]);
    assert!(out.lines().next().unwrap().ends_with(" · C2 node · Pi A"), "{out}");
    let (_, s) = a.req("GET", "/api/sessions/sensor", None);
    assert!(s["local_seen_as"].as_str().unwrap().starts_with("127.0.0.1:"));
}

fn latch_api() -> Api {
    let a = api(Opts { allow_transmit: true, extra: json!({"features": {"transmit_control": true}}), ..Default::default() });
    assert!(wait_for(|| a.session().with(|i| i.sock.is_some()), 2.0));
    a
}

mod latch_cli {
    use super::*;

    #[test]
    fn test_cli_without_arm_refuses_and_says_what_it_would_do() {
        let a = latch_api();
        let (code, _, err) = a.cli(&["action", "sensor", "transmit_on"]);
        assert_eq!(code, 1);
        assert!(err.contains("locked"));
        assert!(err.contains("--arm"));
    }

    #[test]
    fn test_cli_arm_with_confirm() {
        let a = latch_api();
        let (code, out, err) = a.cli(&["action", "sensor", "transmit_on", "--arm", "--confirm", "1"]);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("ARMED"));
        assert!(out.contains("Re-locked"));
        let (code, _, err) = a.cli(&["action", "sensor", "transmit_on", "--arm", "--confirm", "7"]);
        assert_eq!(code, 1);
        assert!(err.contains("did not match"));
        let ev = a.session().get_events(50);
        assert!(ev.iter().any(|e| e["kind"] == "fire" && e["source"] == "cli"));
    }

    #[test]
    fn test_api_fire_without_token_refused() {
        let a = latch_api();
        assert_eq!(a.req("POST", "/api/sessions/sensor/actions/transmit_on", Some(json!({"confirm": "1"}))).0, 403);
        let (code, arm) = a.req("POST", "/api/sessions/sensor/arm/transmit_on", Some(json!({})));
        assert_eq!(code, 200);
        let (code, r) = a.req("POST", "/api/sessions/sensor/actions/transmit_on", Some(json!({"confirm": "1", "token": arm["token"]})));
        assert_eq!(code, 200, "{r}");
    }
}
