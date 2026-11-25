// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_node.py: this node's addresses and roles, from `ip -j` output.

use crate::core::tempdir;
use scapegoat::{cli, node};
use serde_json::{json, Value};

// Shapes from `ip -j addr` / `ip -j route` on Ubuntu 24.04 arm64 (Raspberry Pi), trimmed.
fn ip_addr() -> String {
    json!([
        {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UNKNOWN",
         "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}, {"family": "inet6", "local": "::1", "prefixlen": 128}]},
        {"ifindex": 2, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "192.0.2.177", "prefixlen": 24}, {"family": "inet6", "local": "fe80::2ecf:67ff:fe01:203", "prefixlen": 64}]},
        {"ifindex": 3, "ifname": "wlan0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP",
         "addr_info": [{"family": "inet", "local": "10.20.30.41", "prefixlen": 24}]},
        {"ifindex": 4, "ifname": "wt0", "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"], "operstate": "UNKNOWN",
         "addr_info": [{"family": "inet", "local": "100.127.12.7", "prefixlen": 16}]},
        {"ifindex": 5, "ifname": "podman0", "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"], "operstate": "DOWN",
         "addr_info": [{"family": "inet", "local": "10.88.0.1", "prefixlen": 16}]},
        {"ifindex": 6, "ifname": "end1", "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"], "operstate": "DOWN",
         "addr_info": [{"family": "inet", "local": "172.16.5.2", "prefixlen": 24}]},
    ])
    .to_string()
}

fn ip_route() -> String {
    json!([
        {"dst": "default", "gateway": "10.20.30.1", "dev": "wlan0", "protocol": "dhcp", "prefsrc": "10.20.30.41", "metric": 600},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "protocol": "dhcp", "prefsrc": "192.0.2.177", "metric": 100},
        {"dst": "192.0.2.0/24", "dev": "eth0", "protocol": "kernel", "scope": "link"},
    ])
    .to_string()
}

fn build(billie: Value, loopback: bool) -> Value {
    let rows = node::parse_ip_addr(&ip_addr());
    node::build(
        &rows,
        &node::parse_ip_route(&ip_route()),
        &["192.0.2.81".into(), "192.0.2.74".into()],
        "192.0.2.177/24",
        "node-b",
        billie,
        loopback,
    )
}

fn by<'a>(n: &'a Value, iface: &str) -> &'a Value {
    n["addresses"].as_array().unwrap().iter().find(|a| a["iface"] == iface).unwrap()
}

#[test]
fn test_roles_and_order() {
    let n = build(Value::Null, false);
    let got: Vec<(String, String, String)> = n["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["role"].as_str().unwrap().into(), a["iface"].as_str().unwrap().into(), a["cidr"].as_str().unwrap().into()))
        .collect();
    let want: Vec<(String, String, String)> = [
        ("sensor LAN", "eth0", "192.0.2.177/24"),
        ("NetBird mesh", "wt0", "100.127.12.7/16"),
        ("wired", "end1", "172.16.5.2/24"),
        ("Wi-Fi", "wlan0", "10.20.30.41/24"),
        ("Billie containers", "podman0", "10.88.0.1/16"),
    ]
    .iter()
    .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
    .collect();
    assert_eq!(got, want);
    assert_eq!(n["loopback_hidden"], 2);
    assert_eq!(n["default_route"]["iface"], "eth0", "lowest metric first");
    assert_eq!((by(&n, "eth0")["default_route"].clone(), by(&n, "eth0")["route_note"].clone()), (json!(true), json!("default route")));
    assert_eq!(
        (by(&n, "wlan0")["default_route"].clone(), by(&n, "wlan0")["route_note"].clone()),
        (json!(false), json!("backup default (metric 600)"))
    );
    assert_eq!(by(&n, "wt0")["route_note"], "");
    assert!(by(&n, "wlan0")["cable"].is_null(), "Wi-Fi shows up/down, not cable");
    assert_eq!((by(&n, "eth0")["link"].clone(), by(&n, "eth0")["cable"].clone()), (json!("up"), json!(true)));
    assert_eq!((by(&n, "end1")["link"].clone(), by(&n, "end1")["cable"].clone()), (json!("no cable"), json!(false)));
}

#[test]
fn test_only_src_address_marked() {
    let two = json!([{"ifname": "eth0", "flags": ["UP", "LOWER_UP"], "operstate": "UP",
                      "addr_info": [{"local": "192.0.2.177", "prefixlen": 24}, {"local": "198.51.100.212", "prefixlen": 24}]}])
    .to_string();
    let route = json!([{"dst": "default", "dev": "eth0", "prefsrc": "198.51.100.212", "metric": 100}]).to_string();
    let n = node::build(&node::parse_ip_addr(&two), &node::parse_ip_route(&route), &[], "", "pi", Value::Null, false);
    let marks: std::collections::BTreeMap<String, String> = n["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["ip"].as_str().unwrap().into(), a["route_note"].as_str().unwrap().into()))
        .collect();
    assert_eq!(
        marks,
        [("192.0.2.177".to_string(), "".to_string()), ("198.51.100.212".to_string(), "default route".to_string())].into_iter().collect()
    );
}

#[test]
fn test_loopback_on_request() {
    assert!(build(Value::Null, true)["addresses"].as_array().unwrap().iter().any(|a| a["role"] == "loopback"));
}

#[test]
fn test_billie_files() {
    let d = tempdir("billie");
    let (idp, fab) = (d.join("node.yml"), d.join("fabric.json"));
    std::fs::write(&idp, "# billie identity\nnode_handle: node-b-edge\nsite: x\n").unwrap();
    std::fs::write(
        &fab,
        json!({"billie_fabric_prefix": "slot/demo", "zenoh": {"billie_fabric_endpoint": "tls/core.example:7447"}}).to_string(),
    )
    .unwrap();
    let b = node::read_billie(idp.to_str().unwrap(), fab.to_str().unwrap());
    assert_eq!(
        b,
        json!({"node_handle": "node-b-edge", "billie_fabric_prefix": "slot/demo", "billie_fabric_endpoint": "tls/core.example:7447"})
    );
    assert!(node::read_billie("/nonexistent/a", "/nonexistent/b").is_null());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn test_cli_block() {
    let n = build(json!({"node_handle": "node-b-edge", "billie_fabric_prefix": "slot/demo"}), false);
    let text = cli::print_node(&n, "");
    assert!(text.starts_with("This node: node-b   Billie node node-b-edge   slot slot/demo"), "{text}");
    assert!(text.contains("sensor LAN"));
    assert!(text.contains("192.0.2.177/24"));
    assert!(text.contains("no cable, NO CABLE"));
    assert!(text.contains("default route"));
    assert!(text.contains("backup default (metric 600)"));
    let wifi = text.lines().find(|l| l.contains("wlan0")).unwrap();
    assert!(!wifi.contains("cable"));
    assert!(!text.contains("127.0.0.1"));
}
