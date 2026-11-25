// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! A node binary built the way a plugin crate builds one (ADR 0002): the open core, `toy`,
//! and one more protocol, `fake`, the test protocol of tests/fakeproto.py. The Python API
//! and CLI tests run against it over the wire (wire_tests/). Never shipped.

use scapegoat::protocol::{ActionSpec, Decoded, HookResult, LinkState, Plugin, Protocol, Registry};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

fn ka(tx: u16, rx: u16, action: u8) -> Vec<u8> {
    let mut b = b"KA".to_vec();
    b.extend_from_slice(&tx.to_be_bytes());
    b.extend_from_slice(&rx.to_be_bytes());
    b.push(action);
    let s = b.iter().map(|x| *x as u32).sum::<u32>() % 256;
    b.push(s as u8);
    b
}

struct Fake;

impl Protocol for Fake {
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
}

fn create(_: &Map<String, Value>) -> Result<Box<dyn Protocol>, String> {
    Ok(Box::new(Fake))
}

fn main() {
    Registry::new()
        .with(scapegoat::toy::plugin())
        .with(Plugin {
            name: "fake".into(),
            create,
            validate_session: None,
            simulators: vec![],
            profiles: vec![],
            builtin: false,
            config_aliases: Default::default(),
        })
        .install();
    std::process::exit(scapegoat::run(std::env::args().skip(1).collect()));
}
