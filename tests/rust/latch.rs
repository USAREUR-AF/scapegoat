// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_latch.py: the safety latch on sensor-commanding controls, and the owed-reply
//! ledger. (TestLatchCli is in api.rs: it drives the API and the CLI.)

use crate::support::*;
use scapegoat::session::{ActionError, Session};
use serde_json::{json, Map, Value};
use std::time::Duration;

struct Armed {
    sensor: FakeSensor,
    _svc: Running,
    s: Session,
}

fn armed() -> Armed {
    let sensor = FakeSensor::start(0.2);
    let cfg = make_config(
        sensor.port,
        free_udp_port(),
        Opts { allow_transmit: true, extra: json!({"features": {"transmit_control": true}}), ..Default::default() },
    );
    let (svc, s) = start(&cfg, || Box::new(FakeProtocol::default()));
    assert!(wait_for(|| s.with(|i| i.sock.is_some()), 2.0));
    Armed { sensor, _svc: Running(svc), s }
}

fn transmit_sent(sensor: &FakeSensor) -> usize {
    sensor.received.lock().unwrap().iter().filter(|d| d.len() > 6 && &d[..2] == b"KA" && d[6] == 5).count()
}

fn none() -> Map<String, Value> {
    Map::new()
}

fn refused_with(r: Result<Value, ActionError>, want: &str) {
    match r {
        Err(ActionError::Refused(m)) => assert!(m.contains(want), "{m}"),
        other => panic!("expected a refusal with {want:?}, got {other:?}"),
    }
}

#[test]
fn test_locked_control_does_nothing() {
    let a = armed();
    refused_with(a.s.run_action("transmit_on", &json!("1"), "ui", &none(), None, ""), "locked");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(transmit_sent(&a.sensor), 0);
}

#[test]
fn test_arm_send_relocks() {
    let a = armed();
    let arm = a.s.arm("transmit_on", "ui", "10.0.0.9", &none()).unwrap();
    let tok = arm["token"].as_str().unwrap().to_string();
    let r = a.s.run_action("transmit_on", &json!("1"), "ui", &none(), Some(&tok), "10.0.0.9").unwrap();
    assert_eq!(r["ok"], true);
    assert!(wait_for(|| transmit_sent(&a.sensor) == 1, 2.0));
    refused_with(a.s.run_action("transmit_on", &json!("1"), "api", &none(), Some(&tok), ""), "locked"); // one shot
    let kinds: Vec<String> = a.s.with(|i| i.events.iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect());
    assert!(kinds.contains(&"arm".to_string()));
    assert!(kinds.contains(&"fire".to_string()));
    let t = a.s.get_traffic(None, 100);
    let ctl: Vec<&Value> = t["entries"].as_array().unwrap().iter().filter(|e| e["direction"] == "ctl").collect();
    assert_eq!(ctl.iter().take(2).map(|e| e["fields"]["what"].as_str().unwrap()).collect::<Vec<_>>(), vec!["arm", "fire"]);
    assert_eq!(ctl[0]["fields"]["who"], "10.0.0.9");
}

#[test]
fn test_arm_expires() {
    let a = armed();
    a.s.with(|i| i.arm_window_s = 0.2);
    let arm = a.s.arm("transmit_on", "cli", "op@host", &none()).unwrap();
    assert!(wait_for(|| has_event(&a.s, |e| e["kind"] == "timeout"), 2.0));
    refused_with(a.s.run_action("transmit_on", &json!("1"), "api", &none(), arm["token"].as_str(), ""), "locked");
    assert_eq!(transmit_sent(&a.sensor), 0);
}

#[test]
fn test_wrong_device_id_refuses_and_relocks() {
    let a = armed();
    let arm = a.s.arm("transmit_on", "api", "", &none()).unwrap();
    refused_with(a.s.run_action("transmit_on", &json!("2"), "api", &none(), arm["token"].as_str(), ""), "device ID");
    refused_with(a.s.run_action("transmit_on", &json!("1"), "api", &none(), arm["token"].as_str(), ""), "locked");
    assert!(has_event(&a.s, |e| e["kind"] == "cancel"));
    assert_eq!(transmit_sent(&a.sensor), 0);
}

#[test]
fn test_disarm() {
    let a = armed();
    a.s.arm("transmit_on", "api", "", &none()).unwrap();
    a.s.disarm("transmit_on", "ui", "10.0.0.9");
    assert!(a.s.with(|i| i.arms.is_empty()));
    assert!(has_event(&a.s, |e| e["kind"] == "cancel"));
}

#[test]
fn test_feature_false_hides() {
    let a = armed();
    a.s.with(|i| i.cfg.transmit_feature = false);
    assert!(!a.s.actions().iter().any(|x| x.name == "transmit_on"));
    refused_with(a.s.arm("transmit_on", "api", "", &none()), "feature flag");
}

#[test]
fn test_unanswered_message_becomes_a_problem() {
    let sensor = FakeSensor::start(0.2);
    let cfg = make_config(sensor.port, free_udp_port(), Opts::default());
    let s = Session::new(cfg.sessions[0].clone(), Some(Box::new(FakeProtocol { owes_data: true, ..Default::default() })));
    s.with(|i| i.owed_reply_s = 0.3);
    let svc = scapegoat::service::Service::new(cfg, Some(vec![s.clone()]), None).unwrap();
    let _run = Running(svc.clone());
    svc.start_sessions();
    assert!(wait_for(|| sensor.peer().is_some(), 2.0));
    sensor.send(b"DTx");
    assert!(wait_for(|| !s.status(0)["problems"].as_array().unwrap().is_empty(), 3.0));
    let st = s.status(0);
    let p = st["problems"][0]["problem"].as_str().unwrap();
    let re_ok = p.starts_with("owed: answer for Data from the device at ")
        && p.ends_with("Z, unanswered")
        && p.len() == "owed: answer for Data from the device at 00:00:00Z, unanswered".len();
    assert!(re_ok, "{p}");
    assert_eq!(st["owed_replies"]["missed"], 1);
}
