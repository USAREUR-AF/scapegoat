// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_net.py: the network tools against a fake Linux host; nothing touches the real
//! network.

use scapegoat::net::{self, Host};
use serde_json::{json, Map, Value};
use std::sync::Mutex;

fn ip_addr() -> Value {
    json!([
        {"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN",
         "link_type":"loopback","address":"00:00:00:00:00:00",
         "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo"}]},
        {"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,
         "operstate":"UP","link_type":"ether","address":"dc:a6:32:00:00:01",
         "addr_info":[{"family":"inet","local":"10.10.0.5","prefixlen":24,"scope":"global","dynamic":true,
                       "label":"eth0","valid_life_time":86000,"preferred_life_time":86000},
                      {"family":"inet6","local":"fe80::dea6:32ff:fe00:1","prefixlen":64,"scope":"link"}]},
        {"ifindex":3,"ifname":"wlan0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,
         "operstate":"DOWN","link_type":"ether","address":"dc:a6:32:00:00:02","addr_info":[]}
    ])
}

fn ip_link() -> Value {
    Value::Array(
        ip_addr()
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                let mut i = i.clone();
                i.as_object_mut().unwrap().remove("addr_info");
                i
            })
            .collect(),
    )
}

fn ip_neigh() -> Value {
    json!([{"dst":"10.10.0.1","dev":"eth0","lladdr":"00:11:22:33:44:55","state":["REACHABLE"]},
           {"dst":"192.0.2.81","dev":"eth0","state":["FAILED"]}])
}

fn ip_route() -> Value {
    json!([{"dst":"default","gateway":"10.10.0.1","dev":"eth0","protocol":"dhcp","prefsrc":"10.10.0.5","metric":100},
           {"dst":"10.10.0.0/24","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"10.10.0.5"}])
}

fn route_get_via_gw() -> Value {
    json!([{"dst": "192.0.2.81", "gateway": "10.10.0.1", "dev": "eth0", "prefsrc": "10.10.0.5", "flags": [], "uid": 0, "cache": []}])
}

fn route_get_direct() -> Value {
    json!([{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.10", "flags": [], "uid": 0, "cache": []}])
}

const SS_EMPTY: &str = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n";
const SS_SCAPEGOAT: &str = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nUNCONN 0      0            0.0.0.0:47000   0.0.0.0:*     users:((\"python3\",pid=900,fd=5))\n";
const UFW_ACTIVE: &str = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n";
const TCPDUMP_OUT: &str = "12:00:01.123456 eth0  Out IP 192.0.2.10.47000 > 192.0.2.81.47000: UDP, length 16
12:00:01.130001 eth0  In  IP 192.0.2.81.47000 > 192.0.2.10.47000: UDP, length 16
12:00:02.000000 IP 192.0.2.81.47000 > 192.0.2.10.47000: UDP, length 48
12:00:03.000000 IP6 fe80::1.47000 > fe80::2.47000: UDP, length 16
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
";

fn config() -> Value {
    json!({"allow_net_control": false, "node_name": "t", "topology": "same-lan",
           "sessions": {"sensor": {"protocol": "toy", "local": "0.0.0.0:47000", "peer": "192.0.2.81:47000"}}})
}

struct State {
    addr: Value,
    route_get: Value,
    ss: String,
    tools: Vec<String>,
    carriers: Vec<(String, String)>,
    routes: Option<Value>,
    calls: Vec<Vec<String>>,
    neigh_fails: bool,
}

/// Answers commands for a Linux-shaped host.
pub struct FakeHost(Mutex<State>);

impl FakeHost {
    pub fn new(addr: Value, route_get: Value, ss: &str) -> FakeHost {
        FakeHost(Mutex::new(State {
            addr,
            route_get,
            ss: ss.into(),
            tools: ["ip", "ss", "ufw", "tcpdump", "ping"].iter().map(|s| s.to_string()).collect(),
            carriers: vec![],
            routes: None,
            calls: vec![],
            neigh_fails: false,
        }))
    }
    pub fn default_host() -> FakeHost {
        Self::new(ip_addr(), route_get_via_gw(), SS_EMPTY)
    }
    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.st().calls.clone()
    }
}

impl Host for FakeHost {
    fn run(&self, args: &[String], timeout: f64) -> (i32, String, String) {
        assert!(timeout > 0.0, "every call needs a timeout");
        let mut s = self.st();
        s.calls.push(args.to_vec());
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let ok = |v: &Value| (0, v.to_string(), String::new());
        match a.as_slice() {
            ["ip", "-j", "addr", ..] => ok(&s.addr),
            ["ip", "-j", "link", ..] => ok(&ip_link()),
            ["ip", "-j", "neigh", ..] if s.neigh_fails => (1, String::new(), "RTNETLINK answers: boom".into()),
            ["ip", "-j", "neigh", ..] => ok(&ip_neigh()),
            ["ip", "-j", "route", "get", ..] => ok(&s.route_get),
            ["ip", "-j", "route", ..] => ok(&s.routes.clone().unwrap_or(ip_route())),
            ["ss", ..] => (0, s.ss.clone(), String::new()),
            ["ufw", "status", ..] => (0, UFW_ACTIVE.into(), String::new()),
            ["tcpdump", ..] => (124, TCPDUMP_OUT.into(), format!("\ntimed out after {timeout}s").trim().to_string()),
            ["ping", ..] => (
                0,
                "PING 10.10.0.1 56(84) bytes of data.\n64 bytes from 10.10.0.1: icmp_seq=1 ttl=64 time=0.41 ms\n\n--- 10.10.0.1 ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss, time 1002ms\nrtt min/avg/max/mdev = 0.380/0.412/0.450/0.029 ms\n".into(),
                String::new(),
            ),
            _ => (0, String::new(), String::new()),
        }
    }
    fn have(&self, cmd: &str) -> bool {
        self.st().tools.iter().any(|t| t == cmd)
    }
    fn read_sys(&self, path: &str) -> Option<String> {
        if path.ends_with("/carrier") {
            let name = path.split('/').nth(4).unwrap_or("").to_string();
            let s = self.st();
            return Some(s.carriers.iter().find(|(n, _)| *n == name).map(|(_, v)| v.clone()).unwrap_or(if name == "wlan0" {
                "0".into()
            } else {
                "1".into()
            }));
        }
        if path.contains("/statistics/") {
            return Some("42".into());
        }
        None
    }
    fn list_interfaces(&self) -> Vec<String> {
        vec!["eth0".into(), "lo".into(), "wlan0".into()]
    }
    fn system(&self) -> String {
        "Linux".into()
    }
}

fn with_extra_addr(mut addr: Value, idx: usize, local: &str, prefix: i64) -> Value {
    addr[idx]["addr_info"].as_array_mut().unwrap().push(json!({"family": "inet", "local": local, "prefixlen": prefix}));
    addr
}

fn joined(v: &Value) -> String {
    v.as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect::<Vec<_>>().join(" ")
}

fn hints(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect()
}

mod snapshot {
    use super::*;

    #[test]
    fn test_sections_and_interfaces() {
        let h = FakeHost::default_host();
        let s = net::snapshot(&h, &config());
        for key in ["host", "interfaces", "neighbors", "routes", "sessions", "firewall", "hints"] {
            assert!(s.get(key).is_some(), "{key}");
        }
        let eth0 = s["interfaces"].as_array().unwrap().iter().find(|i| i["name"] == "eth0").unwrap();
        assert_eq!(eth0["carrier"], true);
        assert_eq!(eth0["mac"], "dc:a6:32:00:00:01");
        assert!(eth0["addresses"].as_array().unwrap().iter().any(|a| a["cidr"] == "10.10.0.5/24"));
        assert_eq!(eth0["stats"]["rx_bytes"], 42);
        let wlan = s["interfaces"].as_array().unwrap().iter().find(|i| i["name"] == "wlan0").unwrap();
        assert_eq!(wlan["carrier"], false);
    }

    #[test]
    fn test_subnet_hint_when_not_in_peer_subnet() {
        let h = FakeHost::default_host();
        let s = net::snapshot(&h, &config());
        let sess = &s["sessions"][0];
        assert_eq!(sess["same_subnet"], json!([]));
        let text = joined(&sess["hints"]);
        assert!(text.contains("192.0.2.0/24"));
        assert!(text.contains("scapegoat net addr_add --iface eth0"));
        assert!(text.contains("gateway 10.10.0.1"));
        assert!(text.contains("Nothing is listening on UDP 47000"));
        assert!(text.contains("ufw is active"), "{text}");
    }

    #[test]
    fn test_neighbor_failed_on_direct_route() {
        let h = FakeHost::new(with_extra_addr(ip_addr(), 1, "192.0.2.10", 24), route_get_direct(), SS_SCAPEGOAT);
        let sess = net::snapshot(&h, &config())["sessions"][0].clone();
        assert_eq!(sess["same_subnet"], json!([{"iface": "eth0", "cidr": "192.0.2.10/24"}]));
        let text = joined(&sess["hints"]);
        assert!(!text.contains("No address on any interface"));
        assert!(!text.contains("Nothing is listening"));
        assert!(text.contains("does not answer ARP"), "{text}");
    }

    #[test]
    fn test_no_carrier_hint() {
        let h = FakeHost::new(
            with_extra_addr(ip_addr(), 2, "192.0.2.10", 24),
            json!([{"dst": "192.0.2.81", "dev": "wlan0", "prefsrc": "192.0.2.10"}]),
            SS_EMPTY,
        );
        let hs = hints(&net::snapshot(&h, &config())["sessions"][0]["hints"]);
        assert!(hs.iter().any(|x| x.contains("wlan0 has no carrier")), "{hs:?}");
    }

    #[test]
    fn test_section_failure_is_isolated() {
        let h = FakeHost::default_host();
        h.st().neigh_fails = true;
        let s = net::snapshot(&h, &config());
        assert!(s["neighbors"].get("error").is_some());
        assert!(s["interfaces"].is_array());
        assert!(s["sessions"].is_array());
    }

    #[test]
    fn test_attribute_config_and_bad_peer() {
        let h = FakeHost::default_host();
        let cfg =
            json!({"allow_net_control": false, "sessions": {"x": {"local": "0.0.0.0:47000", "peer": "not-an-ip:1", "protocol": "toy"}}});
        let s = net::snapshot(&h, &cfg);
        assert!(s["sessions"][0].get("error").is_some());
    }

    #[test]
    fn test_no_tools_never_crashes() {
        let h = FakeHost::default_host();
        h.st().tools.clear();
        let s = net::snapshot(&h, &config());
        assert!(s["interfaces"].get("error").is_some());
        assert!(s["sessions"].is_array());
    }
}

fn cands() -> Value {
    json!({"allow_net_control": false, "sessions": {"sensor": {"protocol": "toy", "local": "0.0.0.0:47000", "peer_candidates": ["192.0.2.81:47000", "192.0.2.74:47000"]}}})
}

fn with(v: &Value, k: &str, x: Value) -> Value {
    let mut v = v.clone();
    v[k] = x;
    v
}

mod candidates_and_expected_local {
    use super::*;

    fn route_gets(h: &FakeHost) -> Vec<String> {
        h.calls().iter().filter(|c| c.len() > 4 && c[..4] == ["ip", "-j", "route", "get"]).map(|c| c.last().unwrap().clone()).collect()
    }

    #[test]
    fn test_every_candidate_checked() {
        let h = FakeHost::default_host();
        let sess = net::snapshot(&h, &with(&cands(), "topology", json!("same-lan")))["sessions"][0].clone();
        assert_eq!(
            sess["peers"].as_array().unwrap().iter().map(|p| p["ip"].as_str().unwrap()).collect::<Vec<_>>(),
            vec!["192.0.2.81", "192.0.2.74"]
        );
        assert_eq!(sess["peer_ip"], "192.0.2.81");
        let rg = route_gets(&h);
        assert_eq!(rg[rg.len() - 2..], ["192.0.2.81".to_string(), "192.0.2.74".to_string()]);
        for p in sess["peers"].as_array().unwrap() {
            assert!(p.get("neighbor").is_some());
            assert_eq!(p["same_subnet"], json!([]));
        }
        // both candidates share one /24: one subnet hint naming both
        let hs = hints(&sess["hints"]);
        let sub: Vec<&String> = hs.iter().filter(|x| x.contains("No address on any interface is in 192.0.2.0/24")).collect();
        assert_eq!(sub.len(), 1);
        assert!(sub[0].contains("peers 192.0.2.81, 192.0.2.74"));
        let mut d = hs.clone();
        d.sort();
        d.dedup();
        assert_eq!(hs.len(), d.len());
    }

    #[test]
    fn test_peer_and_candidates_deduplicated() {
        let h = FakeHost::default_host();
        let cfg = json!({"sessions": {"sensor": {"local": "0.0.0.0:47000", "peer": "192.0.2.81:47000", "peer_candidates": ["192.0.2.81:47000", "192.0.2.74:47000", "bogus"]}}});
        let sess = net::snapshot(&h, &cfg)["sessions"][0].clone();
        assert_eq!(sess["peers"].as_array().unwrap().len(), 2);
        assert!(hints(&sess["hints"]).iter().any(|x| x.contains("'bogus'")));
    }

    #[test]
    fn test_expected_local_missing() {
        let h = FakeHost::default_host();
        let s = net::snapshot(&h, &with(&cands(), "expected_local_address", json!("192.0.2.177/24")));
        assert_eq!(s["expected_local"]["present"], false);
        assert!(hints(&s["hints"]).contains(&"This node should hold 192.0.2.177/24 on the interface toward the sensor (the sensor learns our address from our keepalives). Add it: scapegoat net addr_add --iface eth0 --cidr 192.0.2.177/24 --confirm".to_string()));
        assert!(!h.calls().iter().any(|c| c.len() >= 3 && c[..3] == ["ip", "addr", "add"]));
    }

    #[test]
    fn test_expected_local_present() {
        let h = FakeHost::new(with_extra_addr(ip_addr(), 1, "192.0.2.177", 24), route_get_direct(), SS_EMPTY);
        let s = net::snapshot(&h, &with(&cands(), "expected_local_address", json!("192.0.2.177/24")));
        assert_eq!(s["expected_local"]["on"], json!(["eth0"]));
        assert_eq!(s["expected_local"]["present"], true);
        assert!(!hints(&s["hints"]).iter().any(|x| x.contains("should hold")));
    }

    #[test]
    fn test_expected_local_wrong_prefix() {
        let h = FakeHost::new(with_extra_addr(ip_addr(), 1, "192.0.2.177", 16), route_get_via_gw(), SS_EMPTY);
        let el = net::snapshot(&h, &with(&cands(), "expected_local_address", json!("192.0.2.177/24")))["expected_local"].clone();
        assert_eq!(el["present"], false);
        assert!(el["hints"][0].as_str().unwrap().contains("prefix differs"));
    }

    #[test]
    fn test_expected_local_unset_and_bad() {
        let h = FakeHost::default_host();
        assert!(net::snapshot(&h, &cands())["expected_local"].is_null());
        let el = net::snapshot(&h, &with(&cands(), "expected_local_address", json!("nonsense")))["expected_local"].clone();
        assert!(el.get("error").is_some());
    }
}

mod sensor_facing {
    use super::*;

    fn exp() -> Value {
        with(&cands(), "expected_local_address", json!("192.0.2.177/24"))
    }

    #[test]
    fn test_expected_key_missing_then_present() {
        let h = FakeHost::default_host();
        assert_eq!(net::snapshot(&h, &exp())["expected_local_address"], json!({"cidr": "192.0.2.177/24", "present_on": null}));
        let h = FakeHost::new(with_extra_addr(ip_addr(), 1, "192.0.2.177", 24), route_get_direct(), SS_EMPTY);
        assert_eq!(net::snapshot(&h, &exp())["expected_local_address"], json!({"cidr": "192.0.2.177/24", "present_on": "eth0"}));
        assert!(net::snapshot(&h, &cands())["expected_local_address"].is_null());
    }

    #[test]
    fn test_iface_choice_skips_wireless_and_virtual() {
        let ifaces = json!([{"name": "lo", "carrier": true}, {"name": "wlan0", "carrier": true}, {"name": "wt0", "carrier": true},
                            {"name": "veth12", "carrier": true}, {"name": "podman0", "carrier": true}, {"name": "eth1", "carrier": false},
                            {"name": "eth0", "carrier": true}]);
        assert_eq!(net::sensor_iface_choice(&ifaces, &[]), "eth0");
        let first6 = Value::Array(ifaces.as_array().unwrap()[..6].to_vec());
        assert_eq!(net::sensor_iface_choice(&first6, &[]), "<iface>");
    }

    #[test]
    fn test_no_eligible_iface_writes_placeholder() {
        let h = FakeHost::default_host();
        h.st().carriers = vec![("eth0".into(), "0".into())];
        let s = net::snapshot(&h, &exp());
        assert!(hints(&s["hints"]).contains(&"This node should hold 192.0.2.177/24 on the interface toward the sensor (the sensor learns our address from our keepalives). Add it: scapegoat net addr_add --iface <iface> --cidr 192.0.2.177/24 --confirm".to_string()));
    }

    #[test]
    fn test_subnet_hint_suggests_expected_address() {
        let h = FakeHost::default_host();
        let hs = hints(&net::snapshot(&h, &exp())["sessions"][0]["hints"]);
        let sub: Vec<&String> = hs.iter().filter(|x| x.starts_with("No address on any interface")).collect();
        assert_eq!(sub.len(), 1);
        assert!(sub[0].contains("--cidr 192.0.2.177/24"));
        assert!(!sub[0].contains("192.0.2.10/24"));
    }

    #[test]
    fn test_sensor_facing_no_carrier() {
        let h = FakeHost::new(with_extra_addr(ip_addr(), 1, "192.0.2.177", 24), route_get_direct(), SS_EMPTY);
        h.st().carriers = vec![("eth0".into(), "0".into())];
        let hs = hints(&net::snapshot(&h, &exp())["hints"]);
        assert!(hs.contains(&"eth0 has no carrier: check the cable to the sensor network switch".to_string()), "{hs:?}");
        assert_eq!(hs.iter().filter(|x| x.contains("has no carrier")).count(), 1);
        assert!(!hs.iter().any(|x| x.starts_with("wlan0 has no carrier")));
    }

    #[test]
    fn test_no_carrier_before_any_address() {
        // sensor subnet not configured yet and the only wired port is dark
        let h = FakeHost::default_host();
        h.st().carriers = vec![("eth0".into(), "0".into())];
        let hs = hints(&net::snapshot(&h, &cands())["hints"]);
        assert!(hs.contains(&"eth0 has no carrier: check the cable to the sensor network switch".to_string()), "{hs:?}");
    }
}

mod parsers {
    use super::*;

    #[test]
    fn test_tcpdump() {
        let pkts = net::parse_tcpdump(TCPDUMP_OUT, 200);
        assert_eq!(pkts.len(), 4);
        assert_eq!(
            pkts[0],
            json!({"time": "12:00:01.123456", "src": "192.0.2.10", "src_port": 47000, "dst": "192.0.2.81", "dst_port": 47000, "length": 16, "iface": "eth0", "direction": "Out"})
        );
        assert!(pkts[2].get("iface").is_none());
        assert_eq!(pkts[2]["length"], 48);
        assert_eq!(pkts[3]["src"], "fe80::1");
        assert!(net::parse_tcpdump_line("garbage line").is_none());
        assert_eq!(net::parse_tcpdump(TCPDUMP_OUT, 2).len(), 2);
    }

    #[test]
    fn test_ss() {
        let rows = net::parse_ss(SS_SCAPEGOAT);
        let mine: Vec<&Value> = rows.as_array().unwrap().iter().filter(|r| r["port"] == 47000).collect();
        assert_eq!(mine[0]["process"], "python3");
        assert_eq!(mine[0]["pid"], 900);
    }

    #[test]
    fn test_ifconfig() {
        let t = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether aa:bb:cc:dd:ee:ff\n\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n\tstatus: active\n";
        let r = net::parse_ifconfig(t);
        assert_eq!(r[0]["addresses"][0]["cidr"], "192.0.2.10/24");
        assert_eq!(r[0]["carrier"], true);
    }

    #[test]
    fn test_split_hostport() {
        assert_eq!(net::split_hostport(&json!("192.0.2.81:47000")).unwrap(), ("192.0.2.81".to_string(), Some(47000)));
        assert_eq!(net::split_hostport(&json!("[fe80::1]:47000")).unwrap(), ("fe80::1".to_string(), Some(47000)));
        assert!(net::split_hostport(&json!("192.0.2.81:99999")).is_err());
    }
}

mod probe {
    use super::*;

    #[test]
    fn test_ping() {
        let h = FakeHost::default_host();
        let r = net::ping(&h, &json!("10.10.0.1"), &json!(3), &json!(5)).unwrap();
        assert_eq!(r["reachable"], true);
        assert_eq!((r["sent"].clone(), r["received"].clone()), (json!(3), json!(3)));
        assert!((r["rtt_avg_ms"].as_f64().unwrap() - 0.412).abs() < 1e-9);
    }

    #[test]
    fn test_ping_rejects_bad_ip() {
        let h = FakeHost::default_host();
        assert!(net::ping(&h, &json!("10.0.0.1; reboot"), &json!(3), &json!(5)).is_err());
        assert!(h.calls().is_empty());
    }

    #[test]
    fn test_capture() {
        let h = FakeHost::default_host();
        let r = net::capture(&h, &json!(47000), &json!(2), &Value::Null, &json!(200)).unwrap();
        assert_eq!(r["count"], 4);
        let cmd: Vec<String> = r["command"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
        assert_eq!(cmd[cmd.len() - 5..], ["udp", "port", "47000", "or", "icmp"].map(String::from));
        assert!(cmd.contains(&"any".to_string()));
        assert!(r.get("error").is_none());
    }

    #[test]
    fn test_capture_validates() {
        let h = FakeHost::default_host();
        assert!(net::capture(&h, &json!(70000), &json!(10), &Value::Null, &json!(200)).is_err());
        assert!(net::capture(&h, &json!(47000), &json!(10), &json!("eth9"), &json!(200)).is_err());
        assert!(h.calls().is_empty());
    }

    #[test]
    fn test_udp_probe_sends_nothing() {
        let h = FakeHost::default_host();
        let r = net::udp_probe(&h, &json!("192.0.2.81"), &json!(47000)).unwrap();
        assert_eq!(r["route"]["gateway"], "10.10.0.1");
        assert!(r["note"].as_str().unwrap().contains("nothing was sent"));
        assert!(!h.calls().iter().any(|c| ["nc", "socat", "tcpdump"].contains(&c[0].as_str())));
    }
}

/// The audit log is one per process, as in Python: the control tests take turns.
static AUDIT_TURN: Mutex<()> = Mutex::new(());

mod control {
    use super::*;

    fn allow() -> Value {
        with(&config(), "allow_net_control", json!(true))
    }

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn mutating(h: &FakeHost) -> Vec<Vec<String>> {
        h.calls()
            .into_iter()
            .filter(|c| {
                c.len() >= 2 && (["addr", "link", "neigh"].contains(&c[1].as_str()) && c[0] == "ip" || (c[0] == "ufw" && c[1] == "allow"))
            })
            .collect()
    }

    #[test]
    fn test_actions_table() {
        for name in ["addr_add", "addr_del", "link_up", "link_down", "neigh_flush", "fw_allow", "ping", "capture"] {
            let a = net::ACTIONS.iter().find(|a| a.name == name).unwrap();
            assert!(!a.label.is_empty() && !a.description.is_empty() && !a.args.is_empty());
        }
        assert!(!net::ACTIONS.iter().find(|a| a.name == "ping").unwrap().dangerous);
        assert!(net::ACTIONS.iter().find(|a| a.name == "link_down").unwrap().dangerous);
    }

    #[test]
    fn test_refused_when_not_allowed() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        let r = net::run(&h, "addr_add", &args(json!({"iface": "eth0", "cidr": "192.0.2.10/24", "confirm": true})), &config());
        assert_eq!(r["ok"], false);
        assert!(r["message"].as_str().unwrap().contains("allow_net_control"));
        assert!(mutating(&h).is_empty());
    }

    #[test]
    fn test_refused_without_confirm() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        let r = net::run(&h, "addr_add", &args(json!({"iface": "eth0", "cidr": "192.0.2.10/24"})), &allow());
        assert_eq!(r["ok"], false);
        assert!(r["message"].as_str().unwrap().contains("confirm"));
        assert_eq!(r["command"], json!(["ip", "addr", "add", "192.0.2.10/24", "dev", "eth0"]));
        assert!(mutating(&h).is_empty());
    }

    #[test]
    fn test_runs_when_allowed_and_confirmed() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        let r = net::run(&h, "addr_add", &args(json!({"iface": "eth0", "cidr": "192.0.2.10/24", "confirm": true})), &allow());
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(mutating(&h), vec![["ip", "addr", "add", "192.0.2.10/24", "dev", "eth0"].map(String::from).to_vec()]);
        let log = net::audit_log();
        assert_eq!(log.last().unwrap()["action"], "addr_add");
        assert!(log.last().unwrap()["args"].get("confirm").is_none());
    }

    #[test]
    fn test_fw_allow_command() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        let r = net::run(
            &h,
            "fw_allow",
            &args(json!({"iface": "eth0", "from_cidr": "192.0.2.0/24", "port": 47000, "confirm": true})),
            &allow(),
        );
        assert_eq!(
            r["command"],
            json!(["ufw", "allow", "in", "on", "eth0", "from", "192.0.2.0/24", "to", "any", "port", "47000", "proto", "udp"])
        );
    }

    #[test]
    fn test_injection_and_bad_args_refused() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        net::audit_clear();
        let h = FakeHost::default_host();
        let bad = [
            ("link_up", json!({"iface": "eth0; rm -rf /"})),
            ("link_up", json!({"iface": "eth9"})),
            ("link_down", json!({"iface": "$(reboot)"})),
            ("addr_add", json!({"iface": "eth0", "cidr": "192.0.2.10"})),
            ("addr_add", json!({"iface": "eth0", "cidr": "192.0.2.10/24 dev lo"})),
            ("addr_add", json!({"iface": "eth0", "cidr": "999.1.1.1/24"})),
            ("fw_allow", json!({"iface": "eth0", "from_cidr": "any", "port": 47000})),
            ("fw_allow", json!({"iface": "eth0", "from_cidr": "10.0.0.0/8", "port": "47000; ls"})),
            ("fw_allow", json!({"iface": "eth0", "from_cidr": "10.0.0.0/8", "port": 0})),
            ("neigh_flush", json!({})),
            ("ping", json!({"ip": "203.0.113.8 -f"})),
            ("capture", json!({"port": "abc"})),
        ];
        for (name, a) in &bad {
            let mut a = args(a.clone());
            a.insert("confirm".into(), json!(true));
            let r = net::run(&h, name, &a, &allow());
            assert_eq!(r["ok"], false, "{name} {a:?}");
            assert!(r["message"].as_str().unwrap().starts_with("refused"), "{name}: {}", r["message"]);
        }
        assert!(h.calls().is_empty());
        assert_eq!(net::audit_log().len(), bad.len());
    }

    #[test]
    fn test_unknown_action() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        let r = net::run(&h, "format_disk", &Map::new(), &allow());
        assert_eq!(r["ok"], false);
        assert!(h.calls().is_empty());
    }

    #[test]
    fn test_ping_passthrough_needs_no_permission() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        let r = net::run(&h, "ping", &args(json!({"ip": "10.10.0.1"})), &config());
        assert_eq!(r["ok"], true);
        assert_eq!(r["result"]["received"], 3);
    }

    #[test]
    fn test_string_confirm_false_is_refused() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        let r = net::run(&h, "link_up", &args(json!({"iface": "eth0", "confirm": "false"})), &allow());
        assert_eq!(r["ok"], false);
    }

    #[test]
    fn test_audit_capped() {
        let _t = AUDIT_TURN.lock().unwrap_or_else(|e| e.into_inner());
        let h = FakeHost::default_host();
        for _ in 0..250 {
            net::run(&h, "link_up", &args(json!({"iface": "eth0"})), &config());
        }
        assert_eq!(net::audit_log().len(), 200);
    }
}

// The field setup: Pi 198.51.100.212/16 on eth0, sensor 192.0.2.81 behind router 198.51.100.1.
fn field_addr() -> Value {
    let mut a = ip_addr();
    a[1]["addr_info"][0]["local"] = json!("198.51.100.212");
    a[1]["addr_info"][0]["prefixlen"] = json!(16);
    a
}

fn field_route_get() -> Value {
    json!([{"dst": "192.0.2.81", "gateway": "198.51.100.1", "dev": "eth0", "prefsrc": "198.51.100.212", "flags": [], "uid": 0, "cache": []}])
}

fn field_cfg() -> Value {
    json!({"node_name": "t", "expected_local_address": "", "sessions": {"sensor": {"protocol": "toy", "local": "0.0.0.0:47000", "peer_candidates": ["192.0.2.81:47000", "192.0.2.74:47000"]}}})
}

mod routed_topology {
    use super::*;

    fn host() -> FakeHost {
        FakeHost::new(field_addr(), field_route_get(), SS_SCAPEGOAT)
    }

    #[test]
    fn test_inferred_routed_gives_no_subnet_advice() {
        let h = host();
        let s = net::snapshot(&h, &field_cfg());
        assert_eq!(s["topology"]["mode"], "routed");
        assert!(s["topology"]["source"].as_str().unwrap().contains("198.51.100.1"));
        let text = joined(&s["hints"]);
        assert!(!text.contains("addr_add"));
        assert!(!text.contains("same subnet"));
        assert!(!text.contains("No address on any interface"));
        assert_eq!(s["sessions"][0]["topology"], "routed");
    }

    #[test]
    fn test_explicit_config_wins() {
        let h = host();
        assert_eq!(
            net::snapshot(&h, &with(&field_cfg(), "topology", json!("same-lan")))["topology"],
            json!({"mode": "same-lan", "source": "config"})
        );
        assert_eq!(
            net::snapshot(&h, &with(&field_cfg(), "expected_local_address", json!("192.0.2.177/24")))["topology"]["mode"],
            "same-lan"
        );
        assert_eq!(
            net::snapshot(&h, &with(&field_cfg(), "topology", json!("routed")))["topology"],
            json!({"mode": "routed", "source": "config"})
        );
    }

    #[test]
    fn test_local_address_in_sensor_subnet_hint_remove() {
        // with that address present the kernel uses the connected /24: no gateway any more
        let h = FakeHost::new(
            with_extra_addr(field_addr(), 1, "192.0.2.177", 24),
            json!([{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.177"}]),
            SS_SCAPEGOAT,
        );
        let s = net::snapshot(&h, &with(&field_cfg(), "topology", json!("routed")));
        let text = joined(&s["hints"]);
        assert!(text.contains("This node holds 192.0.2.177/24 in the sensor's subnet"), "{text}");
        assert!(text.contains("scapegoat net addr_del --iface eth0 --cidr 192.0.2.177/24 --confirm"));
        assert!(!text.contains("addr_add"));
    }

    #[test]
    fn test_never_suggest_removing_the_only_address() {
        let mut addr = field_addr();
        addr[1]["addr_info"][0]["local"] = json!("192.0.2.227");
        addr[1]["addr_info"][0]["prefixlen"] = json!(16);
        let h = FakeHost::new(addr, json!([{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.227"}]), SS_SCAPEGOAT);
        let text = joined(&net::snapshot(&h, &with(&field_cfg(), "topology", json!("routed")))["hints"]);
        assert!(!text.contains("addr_del"));
        assert!(text.contains("own network 192.0.2.227/16 on eth0 includes the sensor address"), "{text}");
    }

    #[test]
    fn test_route_out_wifi_or_mesh() {
        for (dev, word) in [("wlan0", "Wi-Fi"), ("wt0", "NetBird mesh")] {
            let mut rg = field_route_get();
            rg[0]["dev"] = json!(dev);
            let h = FakeHost::new(field_addr(), rg, SS_SCAPEGOAT);
            let text = joined(&net::snapshot(&h, &with(&field_cfg(), "topology", json!("routed")))["hints"]);
            assert!(text.contains(&format!("would leave on {dev} ({word})")), "{text}");
        }
    }
}

#[test]
fn test_parse_and_hint() {
    let sample = "12:00:01.000000 eth0  Out IP 198.51.100.212.47000 > 192.0.2.81.47000: UDP, length 16\n12:00:01.002000 eth0  In  IP 198.51.100.1 > 198.51.100.212: ICMP host 192.0.2.81 unreachable, length 52\n12:00:02.002000 eth0  In  IP 198.51.100.1 > 198.51.100.212: ICMP host 192.0.2.81 unreachable, length 52\n";
    let u = net::icmp_unreachable(sample);
    assert_eq!(
        u.iter().map(|x| (x["router"].as_str().unwrap(), x["target"].as_str().unwrap())).collect::<Vec<_>>(),
        vec![("198.51.100.1", "192.0.2.81")]
    );
    assert_eq!(
        net::unreachable_hints(&u),
        vec!["The router 198.51.100.1 cannot find the sensor at 192.0.2.81: the sensor link not enabled, wrong address, or the sensor not on that segment.".to_string()]
    );
    assert!(net::icmp_unreachable("IP 203.0.113.4.5 > 6.7.8.9.10: UDP, length 3").is_empty());
    let pk = net::parse_tcpdump(sample, 200);
    assert_eq!(
        (pk[1]["src"].clone(), pk[1]["dst"].clone(), pk[1]["src_port"].clone()),
        (json!("198.51.100.1"), json!("198.51.100.212"), Value::Null)
    );
    assert!(pk[1]["icmp"].as_str().unwrap().contains("unreachable"));
}

// node-a in the field: eth0 192.0.2.18/16 by DHCP with the default route; the sensor
// 192.0.2.81 reached through a /32 host route via wlan0; the session bound to wlan0's address.
fn rpi02_addr() -> Value {
    let mut a = ip_addr();
    a[1]["addr_info"][0]["local"] = json!("192.0.2.18");
    a[1]["addr_info"][0]["prefixlen"] = json!(16);
    a[1]["addr_info"][0]["dynamic"] = json!(true);
    a[2]["flags"] = json!(["BROADCAST", "MULTICAST", "UP", "LOWER_UP"]);
    a[2]["operstate"] = json!("UP");
    a[2]["addr_info"] = json!([{"family": "inet", "local": "198.51.100.105", "prefixlen": 16}]);
    a
}

fn rpi02_route_get() -> Value {
    json!([{"dst": "192.0.2.81", "gateway": "198.51.100.1", "dev": "wlan0", "prefsrc": "198.51.100.105", "flags": [], "uid": 0, "cache": []}])
}

mod routed_false_alarms {
    use super::*;

    fn host() -> FakeHost {
        let h = FakeHost::new(rpi02_addr(), rpi02_route_get(), SS_SCAPEGOAT);
        h.st().carriers = vec![("wlan0".into(), "1".into())];
        h
    }

    fn cfg(local: &str) -> Value {
        json!({"topology": "routed", "sessions": {"sensor": {"protocol": "toy", "local": local, "peer_candidates": ["192.0.2.81:47000"]}}})
    }

    #[test]
    fn test_overlap_with_gateway_route_is_only_a_note() {
        let h = host();
        let s = net::snapshot(&h, &cfg("198.51.100.105:47000"));
        let text = joined(&s["hints"]);
        assert!(!text.contains("addr_del"));
        assert!(!text.contains("192.0.2.18/16"));
        let notes = joined(&s["sessions"][0]["notes"]);
        assert!(notes.contains("192.0.2.18/16 on eth0 overlaps the sensor's subnet"));
        assert!(notes.contains("no change needed"));
    }

    #[test]
    fn test_local_bound_to_route_iface_no_wifi_hint() {
        let h = host();
        assert!(!joined(&net::snapshot(&h, &cfg("198.51.100.105:47000"))["hints"]).contains("would leave on wlan0"));
        assert!(joined(&net::snapshot(&h, &cfg("0.0.0.0:47000"))["hints"]).contains("would leave on wlan0 (Wi-Fi)"));
    }

    #[test]
    fn test_never_delete_dhcp_or_default_source_even_on_direct_route() {
        let h = host();
        let mut addr = rpi02_addr();
        addr[1]["addr_info"].as_array_mut().unwrap().push(json!({"family": "inet", "local": "10.9.9.9", "prefixlen": 24}));
        h.st().addr = addr.clone();
        h.st().route_get = json!([{"dst": "192.0.2.81", "dev": "eth0", "prefsrc": "192.0.2.18"}]);
        assert!(
            !joined(&net::snapshot(&h, &cfg("0.0.0.0:47000"))["hints"]).contains("addr_del"),
            "DHCP address must never get a removal command"
        );
        addr[1]["addr_info"][0]["dynamic"] = json!(false); // static, but the default route's source
        h.st().addr = addr;
        h.st().routes = Some(json!([{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0", "prefsrc": "192.0.2.18", "metric": 100}]));
        assert!(
            !joined(&net::snapshot(&h, &cfg("0.0.0.0:47000"))["hints"]).contains("addr_del"),
            "default route source must never get a removal command"
        );
    }
}
