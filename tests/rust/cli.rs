// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_cli.py, plus the CLI-text tests of test_core.py (TestSurfacing, TestPeerKind)
//! and test_traffic.py (TestWatchFormat).

use scapegoat::cli;
use serde_json::{json, Value};

fn snap() -> Value {
    json!({
        "host": {"hostname": "node-b"},
        "interfaces": [
            {"name": "lo", "admin_up": true, "carrier": true, "addresses": [{"cidr": "127.0.0.1/8"}, {"cidr": "::1/128"}]},
            {"name": "eth0", "admin_up": true, "carrier": true, "addresses": [{"cidr": "192.0.2.177/24"}, {"cidr": "fe80::1/64"}]},
            {"name": "wlan0", "admin_up": false, "carrier": false, "addresses": []},
        ],
        "firewall": {"tool": "ufw", "active": true, "default_incoming": "deny", "port_rules": ["47000/udp ALLOW IN 192.0.2.0/24"]},
        "sessions": [{"id": "sensor", "local_port": 47000, "hints": [],
                      "listeners": [{"local": "0.0.0.0", "port": 47000, "process": "python3"}],
                      "peers": [
                          {"ip": "192.0.2.81", "port": 47000, "same_subnet": [{"iface": "eth0", "cidr": "192.0.2.177/24"}],
                           "route": {"iface": "eth0", "gateway": null}, "neighbor": {"state": ["REACHABLE"], "mac": "aa:bb:cc:dd:ee:ff"}},
                          {"ip": "192.0.2.74", "port": 47000, "same_subnet": [], "route": {"iface": "wlan0", "gateway": "10.0.0.1"},
                           "neighbor": {"state": ["NONE"], "mac": null}}]}],
        "expected_local": {"cidr": "192.0.2.177/24", "present": true, "on": ["eth0"]},
        "hints": ["Open the port: scapegoat net fw_allow --iface eth0 --from_cidr 192.0.2.0/24 --port 47000 --confirm"],
    })
}

mod net_human {
    use super::*;

    #[test]
    fn test_layout() {
        let out = cli::print_net(&snap());
        assert!(out.starts_with("FIX THESE FIRST\n  1. Open the port"), "{out}");
        assert!(out.contains("       scapegoat net fw_allow --iface eth0 --from_cidr 192.0.2.0/24 --port 47000 --confirm"));
        assert!(out.contains("Node address: [OK] 192.0.2.177/24 present on eth0"));
        assert!(out.contains("eth0"));
        assert!(!out.contains("fe80"));
        assert!(out.contains("(1 more without addresses"));
        assert!(out.contains("192.0.2.81:47000  yes, eth0 192.0.2.177/24"), "{out}");
        assert!(out.contains("REACHABLE aa:bb:cc:dd:ee:ff"));
        assert!(out.contains("NO"));
        assert!(out.contains("via wlan0 gw 10.0.0.1"));
        assert!(out.contains("listeners: 0.0.0.0:47000 (python3)"));
        assert!(out.contains("FIREWALL  ufw: active, default incoming deny; rules for the port: 47000/udp ALLOW IN"));
        assert!(!out.contains('{'));
    }

    #[test]
    fn test_sections_degrade() {
        let out = cli::print_net(&json!({"interfaces": {"error": "ip not found"}, "sessions": {"error": "x"},
                                         "firewall": {"tool": null, "note": "no ufw or nft found"}, "hints": [], "expected_local": null}));
        assert!(out.contains("No problems found"));
        assert!(out.contains("not available: ip not found"));
        assert!(out.contains("FIREWALL  none: no ufw or nft found"));
    }
}

fn parse(argv: &[&str]) -> clap::ArgMatches {
    cli::build_parser().try_get_matches_from(std::iter::once("scapegoat").chain(argv.iter().copied())).unwrap()
}

mod flag_spellings {
    use super::*;

    #[test]
    fn test_both_spellings() {
        for flag in ["--from_cidr", "--from-cidr"] {
            let m = parse(&["net", "fw_allow", "--iface", "eth0", flag, "192.0.2.0/24", "--port", "47000", "--confirm"]);
            let (_, net) = m.subcommand().unwrap();
            let (_, fw) = net.subcommand().unwrap();
            assert_eq!(fw.get_one::<String>("from_cidr").unwrap(), "192.0.2.0/24");
        }
        for flag in ["--profiles-dir", "--profiles_dir"] {
            let m = parse(&["profiles", flag, "/x"]);
            assert_eq!(m.subcommand().unwrap().1.get_one::<String>("profiles_dir").unwrap(), "/x");
        }
    }

    #[test]
    fn test_api_json_before_and_after() {
        let api_json = |m: &clap::ArgMatches| {
            let mut sm = m;
            while let Some((_, x)) = sm.subcommand() {
                sm = x;
            }
            (sm.get_one::<String>("api").cloned(), sm.get_flag("json"))
        };
        assert_eq!(api_json(&parse(&["--api", "http://h:1", "--json", "status"])), (Some("http://h:1".into()), true));
        assert_eq!(api_json(&parse(&["status", "--api", "http://h:2", "--json"])), (Some("http://h:2".into()), true));
        assert_eq!(api_json(&parse(&["net", "show", "--api", "http://h:3"])), (Some("http://h:3".into()), false));
        assert!(api_json(&parse(&["--json", "net", "ping", "203.0.113.4"])).1);
    }
}

#[test]
fn test_shapes() {
    assert!(cli::print_net_result(&json!({"ip": "192.0.2.81", "reachable": true, "sent": 3, "received": 3, "rtt_avg_ms": 0.4}))
        .contains("REACHABLE (3/3 replies, average 0.4 ms)"));
    let out = cli::print_net_result(&json!({"ok": true, "action": "addr_add", "message": "added",
        "command": ["ip", "addr", "add", "192.0.2.177/24", "dev", "eth0"], "stdout": "", "stderr": ""}));
    assert!(out.contains("Done: added"));
    assert!(out.contains("ran: ip addr add 192.0.2.177/24 dev eth0"));
    assert!(cli::print_net_result(&json!({"ok": false, "message": "refused: x"})).contains("FAILED: refused: x"));
    assert!(cli::print_net_result(&json!({"packets": [{"time": "t", "src": "a", "dst": "b", "length": 16}], "count": 1, "seconds": 10}))
        .contains("1 packets in 10 s"));
}

#[test]
fn test_status_and_net() {
    let text = cli::print_status(&[], &json!({"topology": "routed"}), &Value::Null)
        + &cli::print_net(
            &json!({"topology": {"mode": "routed", "source": "inferred from the route to 192.0.2.81 (via gateway 198.51.100.1)"}, "hints": []}),
        );
    assert!(text.contains("Topology: routed (sensor reached through a router"));
    assert!(text.contains("from inferred from the route to 192.0.2.81 (via gateway 198.51.100.1)"));
}

mod identity {
    use super::*;

    #[test]
    fn test_lines() {
        let ident = json!({"hostname": "node-a", "node_role": "C2 node", "role_note": "", "title": "node-a · C2 node",
                           "billie_node": "node-a-edge", "mesh_address": "100.127.12.7", "slot_short": "slot/demo",
                           "sensor_sees": [{"session": "sensor", "address": "198.51.100.105:47000"}]});
        let lines = cli::identity_lines(&ident);
        assert_eq!(lines[0], "node-a · C2 node");
        assert_eq!(
            lines[1],
            "  Billie node node-a-edge  ·  sensor sees us at 198.51.100.105:47000  ·  mesh 100.127.12.7  ·  slot slot/demo"
        );
        let mut unset = ident.clone();
        unset["node_role"] = Value::Null;
        unset["role_note"] = json!("role not set (node_role in scapegoat.toml)");
        unset["title"] = json!("node-a · node-a-edge");
        assert_eq!(cli::identity_lines(&unset)[0], "node-a · node-a-edge   (role not set (node_role in scapegoat.toml))");
        let mut bare = unset.clone();
        bare["billie_node"] = Value::Null;
        bare["title"] = json!("node-a · role not set");
        assert_eq!(cli::identity_lines(&bare)[0], "node-a · role not set (node_role in scapegoat.toml)");
    }

    #[test]
    fn test_net_notes_printed() {
        let out = cli::print_net(&json!({"hints": [], "sessions": [{"id": "sensor", "peers": [], "notes": [
            "192.0.2.18/16 on eth0 overlaps the sensor's subnet, but traffic to 192.0.2.81 still goes via gateway 198.51.100.1 on wlan0; no change needed."]}]}));
        assert!(out.contains("note (sensor): 192.0.2.18/16 on eth0 overlaps"));
    }
}

// ---- from test_core.py
#[test]
fn test_status_cli_line_feature_off() {
    let st = json!({"id": "sensor", "actions": [], "problems": [],
                    "peer_request": {"label": "Peer asks to transmit", "code": 7, "count": 1, "suggested_action": null,
                                     "disabled_reason": "transmit control is disabled on this node"}});
    assert_eq!(
        cli::attention_lines(&st),
        vec!["DEVICE IS ASKING: Peer asks to transmit  (transmit control is disabled on this node)".to_string()]
    );
}

#[test]
fn test_status_cli_lines() {
    let st = json!({"id": "sensor", "actions": [{"name": "transmit_on", "dangerous": true, "allowed": false}],
                    "peer_request": {"label": "Peer asks to transmit", "code": 7, "count": 3, "suggested_action": "transmit_on"},
                    "problems": [{"problem": "x", "count": 2}]});
    let lines = cli::attention_lines(&st);
    assert_eq!(
        lines[0],
        "DEVICE IS ASKING: Peer asks to transmit  -> scapegoat action sensor transmit_on --confirm  (needs allow_transmit_control = true)"
    );
    assert_eq!(lines[1], "PROBLEM: x (x2)");
}

#[test]
fn test_cli_banner_and_column() {
    assert_eq!(
        cli::kind_banner(&json!({"peer_kind": "REAL DEVICE", "peer_seen": "192.0.2.81:47000", "peer_device_id": 3})),
        "### REAL DEVICE 192.0.2.81:47000 (Device ID 3) ###"
    );
    assert!(cli::kind_banner(&json!({"peer_kind": "SIMULATOR"})).contains("SIMULATOR"));
}

// ---- from test_traffic.py (TestWatchFormat)
fn ka() -> Value {
    json!({"seq": 7, "time": "2026-11-21T11:00:50.099Z", "direction": "rx", "peer": "192.0.2.81:47000", "length": 10, "name": "KeepAlive",
           "ok": true, "problems": [], "hex": "4b410a000c000b000000",
           "fields": {"seq": 12, "ack": 11, "ask": 0, "flags": 0}, "summary": "tx=12 rx=11"})
}

#[test]
fn test_line_uses_the_protocol_summary() {
    let line = cli::format_entry(&ka(), false, false);
    assert!(line.starts_with("11:00:50.099  <- 192.0.2.81:47000"), "{line}");
    assert!(line.contains("KeepAlive"));
    assert!(line.contains("tx=12 rx=11"));
    assert!(!line.contains("!!"));
}

#[test]
fn test_bad_fields_hex() {
    let mut e = ka();
    e["ok"] = json!(false);
    e["problems"] = json!(["bad checksum"]);
    e["direction"] = json!("tx");
    let out = cli::format_entry(&e, true, true);
    assert!(out.contains("-> 192.0.2.81"));
    assert!(out.contains("!! bad checksum"));
    assert!(out.contains("      seq = 12"));
    assert!(out.contains("      4b 41 0a 00"));
}

#[test]
fn test_no_summary_shows_up_to_six_fields() {
    let mut e = ka();
    e["name"] = json!("Data");
    e["fields"] = Value::Object((0..9).map(|i| (format!("f{i}"), json!(i))).collect());
    e.as_object_mut().unwrap().remove("summary");
    let line = cli::format_entry(&e, false, false);
    assert!(line.contains("f5=5"));
    assert!(!line.contains("f6="));
}

// ---- the installer's config check (deploy/field-node/components/scapegoat-field-config)
#[test]
fn test_check_config() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let run = |argv: &[&str]| crate::api::run_cli(argv.iter().map(|s| s.to_string()).collect());
    let (code, out, err) = run(&["check-config", root.join("deploy/scapegoat.example.toml").to_str().unwrap()]);
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    let d = crate::core::tempdir("checkconfig");
    let bad = d.join("bad.toml");
    std::fs::write(&bad, "[sessions.a]\nprotocol = \"toy\"\n").unwrap();
    let (code, _, err) = run(&["check-config", bad.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("config problem: sessions.a.peer is required"), "{err}");
    let _ = std::fs::remove_dir_all(&d);
}
