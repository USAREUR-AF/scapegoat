// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_traffic.py: the tcpdump parser, the traffic log and ICMP hints.
//! (TestWatchFormat is in cli.rs: it tests the CLI's lines.)

use crate::support::*;
use scapegoat::traffic;
use serde_json::{json, Value};

// `tcpdump -nn -l -x -i any udp port 47000` on Ubuntu 24.04 (tcpdump 4.99): a keepalive out,
// and one back padded to the 46-byte Ethernet minimum (padding must be cut).
pub const SAMPLE: &str = "tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
12:00:01.123456 eth0  Out IP 192.0.2.177.47000 > 192.0.2.81.47000: UDP, length 16
\t0x0000:  4500 002c 1c46 4000 4011 0000 c000 02b1
\t0x0010:  c000 0251 b798 b798 0018 0000 4b41 1000
\t0x0020:  0001 0000 0000 0000 0000 00d1
12:00:01.130021 eth0  In  IP 192.0.2.81.47000 > 192.0.2.177.47000: UDP, length 16
\t0x0000:  4500 002c 0000 4000 4011 0000 c000 0251
\t0x0010:  c000 02b1 b798 b798 0018 0000 4b41 1001
\t0x0020:  0001 0001 0000 0000 0000 00d3 0000
2 packets captured
";

#[test]
fn test_parse_sample() {
    let pk = traffic::parse_tcpdump_x(SAMPLE);
    assert_eq!(pk.len(), 2);
    assert_eq!(pk[0].src, "192.0.2.177:47000");
    assert_eq!(pk[0].dst, "192.0.2.81:47000");
    assert_eq!(traffic::hex(&pk[0].payload), "4b4110000001000000000000000000d1");
    assert_eq!(pk[1].time, "12:00:01.130021");
    assert_eq!(pk[1].payload.len(), 16, "Ethernet padding is cut by UDP length");
}

#[test]
fn test_non_udp_ignored() {
    let tcp = "12:00:02.000000 IP 10.0.0.1.22 > 10.0.0.2.5000: Flags [S]\n\t0x0000:  4500 0028 0000 4000 4006 0000 0a00 0001\n\t0x0010:  0a00 0002 0016 1388 0000 0000 0000 0000\n";
    assert!(traffic::parse_tcpdump_x(tcp).is_empty());
}

#[test]
fn test_json_safe() {
    // Fields are JSON values in Rust; bytes are given as hex by the protocol, and a traffic
    // entry carries the fields unchanged.
    let m = scapegoat::protocol::Decoded {
        fields: json!({"a": traffic::hex(b"\x01"), "b": [1, 2], "3": "x"}).as_object().unwrap().clone(),
        ..Default::default()
    };
    let e = traffic::make_entry("rx", "p", b"", Some(&m), None);
    assert_eq!(e["fields"], json!({"a": "01", "b": [1, 2], "3": "x"}));
}

#[test]
fn test_every_datagram_logged_and_since_paging() {
    let sensor = FakeSensor::start(0.2);
    let cfg = make_config(sensor.port, free_udp_port(), Opts { forward: vec!["127.0.0.1:9".into()], ..Default::default() });
    let (svc, s) = start(&cfg, || Box::new(FakeProtocol::default()));
    let _run = Running(svc);
    assert!(wait_for(|| s.state() == "established", 5.0));
    let all = s.get_traffic(None, 2000);
    let entries = all["entries"].as_array().unwrap();
    let dirs: std::collections::BTreeSet<&str> = entries.iter().map(|e| e["direction"].as_str().unwrap()).collect();
    assert_eq!(dirs, ["fwd", "rx", "tx"].into_iter().collect());
    for k in ["seq", "time", "direction", "peer", "length", "name", "ok", "problems", "fields", "hex"] {
        assert!(entries[0].get(k).is_some(), "{k}");
    }
    let seqs: Vec<i64> = entries.iter().map(|x| x["seq"].as_i64().unwrap()).collect();
    let mut sorted = seqs.clone();
    sorted.sort();
    assert_eq!(seqs, sorted);
    let mid = seqs[seqs.len() / 2];
    let page = s.get_traffic(Some(mid), 3);
    assert_eq!(
        page["entries"].as_array().unwrap().iter().map(|x| x["seq"].as_i64().unwrap()).collect::<Vec<_>>(),
        vec![mid + 1, mid + 2, mid + 3]
    );
    assert_eq!(s.get_traffic(Some(all["last_seq"].as_i64().unwrap() + 1000), 200)["entries"], json!([]));
    let ka: &Value = entries.iter().find(|x| x["direction"] == "rx").unwrap();
    assert_eq!(ka["name"], "KeepAlive");
    assert_eq!(ka["length"], 8);
}

const ICMP_SAMPLE: &str = "12:00:01.123456 eth0  Out IP 198.51.100.212.47000 > 192.0.2.81.47000: UDP, length 16
\t0x0000:  4500 002c 1c46 4000 4011 0000 c633 64d4
\t0x0010:  c000 0251 b798 b798 0018 0000 4b41 1000
\t0x0020:  0001 0000 0000 0000 0000 00d1
12:00:01.125000 eth0  In  IP 198.51.100.1 > 198.51.100.212: ICMP host 192.0.2.81 unreachable, length 52
\t0x0000:  4500 0048 0000 0000 4001 0000 c633 6401
\t0x0010:  c633 64d4 0301 0000 0000 0000 4500 002c
";

#[test]
fn test_icmp_hex_not_glued_to_udp_packet() {
    let pk = traffic::parse_tcpdump_x(ICMP_SAMPLE);
    assert_eq!(pk.len(), 1);
    assert_eq!(pk[0].payload.len(), 16);
}

#[test]
fn test_unreachable_hint() {
    let u = traffic::icmp_unreachable(ICMP_SAMPLE);
    assert_eq!(u.len(), 1);
    assert_eq!(
        u[0]["hint"],
        "The router 198.51.100.1 cannot find the sensor at 192.0.2.81: the sensor link not enabled, wrong address, or the sensor not on that segment."
    );
}
