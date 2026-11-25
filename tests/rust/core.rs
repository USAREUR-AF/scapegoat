// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_core.py, test for test.

use crate::support::*;
use scapegoat::config::{self, ConfigError};
use scapegoat::protocol::{load_protocol, ActionSpec, Decoded, LinkState};
use scapegoat::service::Service;
use scapegoat::session::{ActionError, Session, KIND_SIM, REPEAT_LOG_EVERY_S};
use serde_json::{json, Map, Value};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn tempdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("scapegoat-test-{tag}-{}-{}", std::process::id(), scapegoat::clock::mono().to_bits()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn none() -> Map<String, Value> {
    Map::new()
}

mod link_state {
    use super::*;
    #[test]
    fn test_counter_wraps_to_one() {
        let mut link = LinkState { tx_counter: 65534, ..Default::default() };
        assert_eq!(link.next_tx(), 65535);
        assert_eq!(link.next_tx(), 1);
        assert_eq!(LinkState::default().next_tx(), 1);
    }
}

mod config_tests {
    use super::*;

    #[test]
    fn test_toml_and_mapping_access() {
        let cfg = config::load(root().join("deploy/scapegoat.example.toml").to_str().unwrap(), None).unwrap();
        let s = cfg.session("sensor").unwrap();
        assert_eq!(s.peer_addr().unwrap(), ("127.0.0.1".to_string(), 47001));
        assert!(!s.allow_transmit_control);
        assert_eq!(cfg.raw["sessions"]["sensor"]["protocol"], "toy");
        assert_eq!(cfg.get("bind").unwrap(), "127.0.0.1:8730");
    }

    #[test]
    fn test_json_config() {
        let d = tempdir("json");
        let f = d.join("c.json");
        std::fs::write(&f, r#"{"sessions": {"a": {"protocol": "toy", "peer": "10.0.0.1:47000"}}}"#).unwrap();
        let cfg = config::load(f.to_str().unwrap(), None).unwrap();
        let sc = cfg.session("a").unwrap();
        assert_eq!((sc.local.as_str(), sc.local_addr().unwrap()), ("", ("0.0.0.0".to_string(), 0)));
    }

    #[test]
    fn test_errors_are_plain() {
        let e = config::from_dict(&json!({"sessions": {"a": {"protocol": "toy"}}}), "").unwrap_err();
        assert!(e.0.contains("peer is required"), "{e}");
        let e = config::from_dict(&json!({"sessions": {"a": {"protocol": "toy", "peer": "10.0.0.1"}}}), "").unwrap_err();
        assert!(e.0.contains("IP:PORT"), "{e}");
    }

    #[test]
    fn test_missing_package() {
        assert!(load_protocol("nosuchpkg", &none()).is_err());
    }
}

struct SessionFixture {
    sensor: FakeSensor,
    fwd: UdpSocket,
    local: u16,
    _svc: Running,
    s: Session,
}

fn session_fixture() -> SessionFixture {
    let sensor = FakeSensor::start(0.2);
    let fwd = UdpSocket::bind("127.0.0.1:0").unwrap();
    fwd.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let fport = fwd.local_addr().unwrap().port();
    let local = free_udp_port();
    let cfg = make_config(sensor.port, local, Opts { forward: vec![format!("127.0.0.1:{fport}")], ..Default::default() });
    let (svc, s) = start(&cfg, || Box::new(FakeProtocol::default()));
    SessionFixture { sensor, fwd, local, _svc: Running(svc), s }
}

fn st(s: &Session) -> String {
    s.state()
}

mod session_tests {
    use super::*;

    #[test]
    fn test_handshake_degrade_lose_recover() {
        let f = session_fixture();
        let s = &f.s;
        assert!(wait_for(|| st(s) == "established", 5.0), "{}", s.status(0));
        let states = events_of(s, "state");
        assert!(states.iter().any(|m| m.contains("handshaking -> establishing")), "{states:?}");
        assert!(s.with(|i| i.ka_rx_total) >= 3);
        // keepalives were sent FROM the session socket (the sensor replies to that address)
        assert_eq!(f.sensor.peer().unwrap().port(), f.local);
        assert!(s.with(|i| i.link().tx_counter) > 0);
        assert!(s.with(|i| i.link().rx_counter) > 0);
        f.sensor.set_silent(true);
        assert!(wait_for(|| st(s) == "degraded", 2.0), "{}", st(s));
        assert!(wait_for(|| st(s) == "lost", 2.0), "{}", st(s));
        let n = f.sensor.received_len();
        assert!(wait_for(|| f.sensor.received_len() > n + 1, 2.0), "lost must keep sending keepalives");
        f.sensor.set_silent(false);
        assert!(wait_for(|| st(s) == "established", 5.0), "{}", st(s));
    }

    #[test]
    fn test_forwarding_and_counts() {
        let f = session_fixture();
        assert!(wait_for(|| f.sensor.peer().is_some(), 3.0));
        f.sensor.send(b"DThello");
        let mut buf = [0u8; 2048];
        loop {
            let (n, _) = f.fwd.recv_from(&mut buf).unwrap();
            if &buf[..n] == b"DThello" {
                break;
            }
        }
        let st = f.s.status(0);
        assert!(st["rx_by_name"]["Data"].as_u64().unwrap_or(0) >= 1);
        assert!(st["tx_by_name"]["KeepAlive"].as_u64().unwrap_or(0) >= 1);
        assert_eq!(st["peer_seen"], format!("127.0.0.1:{}", f.sensor.port));
        assert!(st["forwarded"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_bad_datagram_counted() {
        let f = session_fixture();
        assert!(wait_for(|| f.sensor.peer().is_some(), 3.0));
        f.sensor.send(b"KA\x00\x01\x00\x00\x00\xff");
        assert!(wait_for(|| f.s.with(|i| i.bad_datagrams) >= 1, 2.0));
    }

    #[test]
    fn test_actions_and_safety() {
        let f = session_fixture();
        let s = &f.s;
        assert!(wait_for(|| s.with(|i| i.sock.is_some()), 2.0));
        let r = s.run_action("ask_reply", &Value::Bool(false), "cli", &none(), None, "").unwrap();
        assert_eq!(r["ok"], true);
        assert!(matches!(s.run_action("transmit_on", &Value::Bool(true), "cli", &none(), None, ""), Err(ActionError::Refused(_))));
        assert!(matches!(s.run_action("nope", &Value::Bool(false), "api", &none(), None, ""), Err(ActionError::Unknown(_))));
        let ev: Vec<Map<String, Value>> =
            s.with(|i| i.events.iter().filter(|e| e["kind"] == "action" || e["kind"] == "refused").cloned().collect());
        assert!(ev.iter().any(|e| e["source"] == "cli" && e["message"].as_str().unwrap().contains("ask_reply")));
        assert!(ev.iter().any(|e| e["message"].as_str().unwrap().contains("transmit_on refused")));
    }

    #[test]
    fn test_feature_off_hides_and_refuses_even_with_allow_and_confirm() {
        let f = session_fixture();
        let s = &f.s;
        s.with(|i| i.cfg.allow_transmit_control = true);
        assert!(wait_for(|| s.with(|i| i.sock.is_some()), 2.0));
        assert!(!s.actions().iter().any(|a| a.name == "transmit_on"));
        assert!(!s.status(0)["actions"].as_array().unwrap().iter().any(|a| a["name"] == "transmit_on"));
        for name in ["transmit_on", "transmit_off"] {
            match s.run_action(name, &Value::Bool(true), "api", &none(), None, "") {
                Err(ActionError::Refused(m)) => assert!(m.contains("features.transmit_control = false"), "{m}"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn test_transmit_needs_allow_and_confirm() {
        let f = session_fixture();
        let s = &f.s;
        s.with(|i| i.cfg.transmit_feature = true);
        assert!(s.actions().iter().any(|a| a.name == "transmit_on"));
        s.with(|i| i.cfg.allow_transmit_control = true);
        assert!(wait_for(|| s.with(|i| i.sock.is_some()), 2.0));
        match s.run_action("transmit_on", &json!("1"), "api", &none(), None, "") {
            Err(ActionError::Refused(m)) => assert!(m.contains("locked"), "{m}"),
            other => panic!("{other:?}"),
        }
        let tok = s.arm("transmit_on", "cli", "tester", &none()).unwrap()["token"].as_str().unwrap().to_string();
        assert_eq!(s.run_action("transmit_on", &json!("1"), "api", &none(), Some(&tok), "").unwrap()["ok"], true);
    }

    #[test]
    fn test_disable_enable_reset() {
        let f = session_fixture();
        let s = &f.s;
        assert!(wait_for(|| st(s) == "established", 5.0));
        s.disable("ui");
        assert_eq!(st(s), "disabled");
        assert!(matches!(s.run_action("ping", &Value::Bool(false), "api", &none(), None, ""), Err(ActionError::Failed(_))));
        s.enable("ui").unwrap();
        assert!(wait_for(|| st(s) == "established", 5.0), "{}", st(s));
        s.reset("ui");
        assert!(["handshaking", "establishing"].contains(&st(s).as_str()));
        assert!(s.with(|i| i.ka_rx_total) <= 1);
        assert!(wait_for(|| st(s) == "established", 5.0), "{}", st(s));
    }
}

const SILENT: &str = "127.0.0.2:9"; // never answers; traffic stays on this machine

mod peer_candidates {
    use super::*;

    fn fixture() -> (FakeSensor, Running, Session) {
        let sensor = FakeSensor::start(0.2);
        let cfg = make_config(
            sensor.port,
            free_udp_port(),
            Opts { candidates: Some(vec![SILENT.into(), format!("127.0.0.1:{}", sensor.port)]), ..Default::default() },
        );
        let (svc, s) = start(&cfg, || Box::new(FakeProtocol::default()));
        (sensor, Running(svc), s)
    }

    fn silent_tx(s: &Session) -> i64 {
        s.with(|i| i.link_of(&("127.0.0.2".into(), 9)).unwrap().tx_counter)
    }

    #[test]
    fn test_probe_all_then_lock_first_answer() {
        let (sensor, _svc, s) = fixture();
        assert!(wait_for(|| s.with(|i| i.locked.is_some()), 3.0));
        assert_eq!(s.with(|i| i.locked.clone()), Some(("127.0.0.1".to_string(), sensor.port)));
        assert!(events_of(&s, "lock").iter().any(|m| m.contains("locked onto 127.0.0.1")));
        assert!(silent_tx(&s) >= 1, "silent candidate was probed");
        let before = silent_tx(&s);
        assert!(wait_for(|| st(&s) == "established", 5.0));
        assert_eq!(silent_tx(&s), before, "no keepalives to others once locked");
        let status = s.status(0);
        assert_eq!(status["locked"], format!("127.0.0.1:{}", sensor.port));
        let c = status["candidates"].as_array().unwrap();
        assert_eq!(c.iter().map(|x| x["locked"].as_bool().unwrap()).collect::<Vec<_>>(), vec![false, true]);
        // each candidate keeps its own counters
        assert!(c[1]["rx_counter"].as_i64().unwrap() > 0);
        assert_eq!(c[0]["rx_counter"], 0);
    }

    #[test]
    fn test_force_lock_and_reset_unlocks() {
        let (sensor, _svc, s) = fixture();
        assert!(wait_for(|| st(&s) == "established", 5.0));
        s.force_lock(SILENT, "cli").unwrap();
        assert_eq!(s.with(|i| i.locked.clone()), Some(("127.0.0.2".to_string(), 9)));
        assert!(wait_for(|| st(&s) == "handshaking", 1.0));
        let n = sensor.received_len();
        std::thread::sleep(Duration::from_millis(500));
        assert!(sensor.received_len() <= n + 1, "real sensor no longer probed");
        s.reset("cli");
        assert!(s.with(|i| i.locked.is_none()));
        assert!(wait_for(|| s.with(|i| i.locked.clone()) == Some(("127.0.0.1".to_string(), sensor.port)), 3.0));
        assert!(matches!(s.force_lock("not-an-address", "api"), Err(ActionError::Failed(_))));
    }
}

mod profiles {
    use super::*;

    #[test]
    fn test_shipped_profiles_parse_and_list() {
        let profs = config::list_profiles(Some("/nonexistent"));
        let sim = profs.iter().find(|p| p["name"] == "sim-local").expect("sim-local listed");
        assert!(!sim["description"].as_str().unwrap().is_empty());
        let cfg = config::from_dict(&Value::Object(config::read(sim["path"].as_str().unwrap()).unwrap()), "").unwrap();
        assert_eq!(cfg.session("sensor").unwrap().protocol, "toy");
        let e = config::from_dict(&json!({"topology": "bridged"}), "").unwrap_err();
        assert!(e.0.contains("topology"));
    }

    #[test]
    fn test_site_overrides_profile() {
        let d = tempdir("profiles");
        let w = |name: &str, text: &str| {
            let p = d.join(name);
            std::fs::write(&p, text).unwrap();
            p.to_string_lossy().to_string()
        };
        w(
            "base.toml",
            "# base\nnode_name = \"p\"\n[sessions.sensor]\nprotocol = \"fake\"\npeer_candidates = [\"10.0.0.1:47000\"]\n[sessions.sensor.protocol_settings]\ndevice_id = 1\ninterface = \"A\"\n",
        );
        let site = w(
            "site.toml",
            &format!(
                "profile = \"base\"\nprofiles_dir = \"{}\"\nnode_name = \"site\"\n[sessions.sensor.protocol_settings]\ndevice_id = 7\n",
                d.display()
            ),
        );
        let cfg = config::load(&site, None).unwrap();
        let ps = &cfg.session("sensor").unwrap().protocol_settings;
        assert_eq!((cfg.node_name.as_str(), ps["device_id"].as_i64().unwrap(), ps["interface"].as_str().unwrap()), ("site", 7, "A"));
        assert_eq!(cfg.profile, "base");
        // CLI --profile wins over the file's profile key
        w("other.toml", "[sessions.sensor]\nprotocol = \"fake\"\npeer = \"10.0.0.9:1\"\n");
        let other = config::load(&site, Some("other")).unwrap();
        assert_eq!(other.session("sensor").unwrap().candidate_addrs().unwrap(), vec![("10.0.0.9".to_string(), 1)]);
        let e = config::load(&site, Some("nope")).unwrap_err();
        assert!(e.0.contains("Available"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn test_only_session() {
        let cfg = config::from_dict(
            &json!({"sessions": {
                "a": {"protocol": "fake", "peer": "127.0.0.1:1", "enabled": false},
                "b": {"protocol": "fake", "peer": "127.0.0.1:2", "enabled": false}}}),
            "",
        )
        .unwrap();
        assert_eq!(Service::new(cfg.clone(), None, Some("b")).unwrap().session_ids(), vec!["b"]);
        assert!(Service::new(cfg, None, Some("zzz")).is_err());
    }
}

fn surfacing_session() -> Session {
    let cfg = make_config(free_udp_port(), free_udp_port(), Opts::default());
    Session::new(cfg.sessions[0].clone(), fake())
}

fn msg(fields: Value, values: Value) -> Decoded {
    Decoded { fields: fields.as_object().unwrap().clone(), values: values.as_object().unwrap().clone(), ..Default::default() }
}

mod surfacing {
    use super::*;

    #[test]
    fn test_problem_rate_limit() {
        let s = surfacing_session();
        let text = "KeepAlive: device_id 9 does not match configured device_id 7";
        for i in 0..5 {
            s.with(|x| x.note_problem(text, 100.0 + i as f64, ""));
        }
        assert_eq!(events_of(&s, "problem").len(), 1);
        s.with(|x| x.note_problem(text, 100.0 + REPEAT_LOG_EVERY_S + 1.0, ""));
        let ev = events_of(&s, "problem");
        assert_eq!(ev.len(), 2);
        assert!(ev.last().unwrap().contains("seen 6 times"));
        assert_eq!(s.status(0)["problems"][0]["count"], 6);
    }

    #[test]
    fn test_peer_request_and_status() {
        let cfg = make_config(free_udp_port(), free_udp_port(), Opts::default());
        let p = FakeProtocol { actions_override: Some(vec![ActionSpec::new("transmit_on", "On", true, "")]), ..Default::default() };
        let s = Session::new(cfg.sessions[0].clone(), Some(Box::new(p)));
        let mut m = msg(json!({"request": "Peer asks to transmit", "sensor_status": "Not transmitting"}), json!({"request": 4}));
        s.with(|x| x.on_peer_keepalive_fields(&m, 10.0));
        let st = s.status(0);
        assert!(st["peer_request"]["suggested_action"].is_null(), "feature off: no button");
        assert_eq!(st["peer_request"]["disabled_reason"], "transmit control is disabled on this node");
        s.with(|x| x.cfg.transmit_feature = true);
        let st = s.status(0);
        assert_eq!(st["peer_request"]["suggested_action"], "transmit_on");
        assert_eq!(st["peer_request"]["disabled_reason"], "");
        assert_eq!(st["peer_status"]["sensor_status"], "Not transmitting");
        m.fields.insert("request".into(), json!("None"));
        m.values.insert("request".into(), json!(0));
        s.with(|x| x.on_peer_keepalive_fields(&m, 11.0));
        assert!(s.status(0)["peer_request"].is_null());
        assert_eq!(s.with(|x| x.events.iter().filter(|e| e["message"].as_str().unwrap().starts_with("peer requests")).count()), 1);
    }

    #[test]
    fn test_features_config() {
        let a = config::from_dict(&json!({"sessions": {"a": {"protocol": "x", "peer": "203.0.113.4:1"}}}), "").unwrap();
        assert!(!a.session("a").unwrap().transmit_feature);
        let on = config::from_dict(
            &json!({"features": {"transmit_control": true}, "sessions": {"a": {"protocol": "x", "peer": "203.0.113.4:1"}}}),
            "",
        )
        .unwrap();
        assert!(on.session("a").unwrap().transmit_feature);
        assert!(matches!(config::from_dict(&json!({"features": {"transmit_control": "yes"}}), ""), Err(ConfigError(_))));
        for p in config::list_profiles(Some("/nonexistent")) {
            assert_eq!(config::read(p["path"].as_str().unwrap()).unwrap()["features"]["transmit_control"], true, "{p}");
        }
    }
}

mod config_aliases {
    //! TestConfigAliases: a plugin's CONFIG_ALIASES keeps its old key names working.
    use super::*;
    use scapegoat::protocol::{ConfigAliases, Registry};

    fn with_aliases<R>(f: impl FnOnce() -> R) -> R {
        static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _t = TURN.lock().unwrap_or_else(|e| e.into_inner());
        let mut toy = scapegoat::toy::plugin();
        toy.config_aliases = ConfigAliases {
            session: vec![("old_allow".into(), "allow_transmit_control".into())],
            features: vec![("old_feature".into(), "transmit_control".into())],
        };
        Registry::new().with(toy).install();
        let r = f();
        Registry::new().with(scapegoat::toy::plugin()).install();
        r
    }

    #[test]
    fn test_old_names_are_read() {
        let cfg = with_aliases(|| {
            config::from_dict(&json!({"features": {"old_feature": true}, "sessions": {"a": {"protocol": "toy", "peer": "127.0.0.1:47001", "old_allow": true}}}), "")
        })
        .unwrap();
        assert!(cfg.session("a").unwrap().transmit_feature);
        assert!(cfg.session("a").unwrap().allow_transmit_control);
    }

    #[test]
    fn test_both_names_is_an_error() {
        let r = with_aliases(|| {
            config::from_dict(
                &json!({"sessions": {"a": {"protocol": "toy", "peer": "127.0.0.1:47001", "old_allow": true, "allow_transmit_control": true}}}),
                "",
            )
        });
        let e = r.unwrap_err();
        assert!(e.0.contains("not both"), "{e}");
    }
}

mod peer_kind {
    use super::*;

    fn make(peer: &str) -> Session {
        let cfg =
            config::from_dict(&json!({"sessions": {"sensor": {"protocol": "fake", "peer": peer, "local": "127.0.0.1:0"}}}), "").unwrap();
        Session::new(cfg.sessions[0].clone(), fake())
    }

    fn ka(urn: i64, rid: i64) -> Decoded {
        msg(json!({"sim_tag": urn, "device_id": rid}), json!({"sim_tag": urn, "device_id": rid}))
    }

    #[test]
    fn test_a_protocol_names_its_device() {
        // The core knows no device type: a protocol names it, the setting holding its ID and
        // the keepalive field carrying the peer's ID.
        let cfg = config::from_dict(
            &json!({"sessions": {"sensor": {"protocol": "fake", "peer": "192.0.2.81:47000", "local": "127.0.0.1:0", "protocol_settings": {"pump_no": 12}}}}),
            "",
        )
        .unwrap();
        let p = FakeProtocol { noun: Some(("pump".into(), "pump_no".into(), "unit".into())), ..Default::default() };
        let s = Session::new(cfg.sessions[0].clone(), Some(Box::new(p)));
        assert_eq!(
            s.with(|i| (i.kind_none.clone(), i.kind_real.clone(), i.device_id)),
            ("no pump yet".to_string(), "REAL PUMP".to_string(), 12)
        );
        s.with(|i| {
            i.peer_seen = Some(("192.0.2.81".into(), 47000));
            i.on_peer_keepalive_fields(&msg(json!({"sim_tag": 0, "unit": 5}), json!({"sim_tag": 0, "unit": 5})), 1.0);
        });
        let st = s.status(0);
        assert_eq!(
            (st["peer_kind"].clone(), st["peer_is_real"].clone(), st["peer_device_id"].clone(), st["device_noun"].clone()),
            (json!("REAL PUMP"), json!(true), json!(5), json!("pump"))
        );
    }

    #[test]
    fn test_kinds() {
        let s = make("192.0.2.81:47000");
        assert_eq!(s.with(|i| (i.kind_none.clone(), i.kind_real.clone())), ("no device yet".to_string(), "REAL DEVICE".to_string()));
        assert_eq!(s.with(|i| i.peer_kind()), "no device yet");
        s.with(|i| {
            i.peer_seen = Some(("192.0.2.81".into(), 47000));
            i.on_peer_keepalive_fields(&ka(0, 3), 1.0);
        });
        assert_eq!(s.with(|i| i.peer_kind()), "REAL DEVICE");
        let st = s.status(0);
        assert_eq!((st["peer_kind"].clone(), st["peer_device_id"].clone()), (json!("REAL DEVICE"), json!(3)));
        s.with(|i| i.on_peer_keepalive_fields(&ka(0xFFFFFF, 3), 2.0));
        assert_eq!(s.with(|i| i.peer_kind()), KIND_SIM, "simulator mark wins on any address");
        let s2 = make("127.0.0.1:47001");
        s2.with(|i| {
            i.peer_seen = Some(("127.0.0.1".into(), 47001));
            i.on_peer_keepalive_fields(&ka(0, 3), 1.0);
        });
        assert_eq!(s2.with(|i| i.peer_kind()), KIND_SIM, "loopback peer is a simulator");
        s2.with(|i| i.log_kind());
        assert!(has_event(&s2, |e| e["kind"] == "kind" && e["message"].as_str().unwrap().contains("SIMULATOR")));
    }
}

mod local_seen_as {
    use super::*;

    #[test]
    fn test_wildcard_bind_uses_source_toward_peer() {
        let mk = |local: &str| {
            let cfg =
                config::from_dict(&json!({"sessions": {"sensor": {"protocol": "fake", "peer": "127.0.0.1:47001", "local": local}}}), "")
                    .unwrap();
            Session::new(cfg.sessions[0].clone(), fake()).local_seen_as()
        };
        assert_eq!(mk("0.0.0.0:47000"), "127.0.0.1:47000");
        assert_eq!(mk("198.51.100.105:47000"), "198.51.100.105:47000");
        assert_eq!(config::from_dict(&json!({"node_role": " C2 node "}), "").unwrap().node_role, "C2 node");
    }
}
