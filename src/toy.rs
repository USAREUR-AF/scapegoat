// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! toy: a small, fully documented demonstration protocol (open, no sensor behind it).
//!
//! It exercises everything the core does with a real protocol: a keepalive with its own
//! sequence number and the last one it saw, a peer that waits for us to speak first, a peer
//! request,
//! several messages in one datagram, and a data message that is forwarded.
//!
//! Wire format, big-endian; every message starts with a 2-byte tag and its total length:
//!
//! ```text
//!   KA  b"KA" len(1)=10 seq(2) ack(2) ask(1) flags(1)  sum(1)    keepalive
//!       seq: this side's keepalive count; ack: the last seq seen from the other side;
//!       ask: 0 none, 1 "reply with a keepalive now"; flags bit 0: sent by the simulator
//!   DT  b"DT" len(1)=n  payload(n-4)                  sum(1)    data (no reply)
//! sum = byte sum of everything before it, mod 256.
//! ```

use crate::protocol::{ActionSpec, Decoded, HookResult, LinkState, Plugin, Protocol, Split};
use serde_json::{json, Map, Value};

pub const KA_LEN: u8 = 10;
pub const ASK_REPLY: u8 = 1;
pub const SIMULATOR_FLAG: u8 = 0x01;
pub const SIM_LOCAL_PROFILE: &str = include_str!("../profiles/sim-local.toml");

fn with_sum(mut body: Vec<u8>) -> Vec<u8> {
    let s = body.iter().map(|b| *b as u32).sum::<u32>() % 256;
    body.push(s as u8);
    body
}

pub fn keepalive_bytes(seq: u16, ack: u16, ask: u8, flags: u8) -> Vec<u8> {
    let mut b = b"KA".to_vec();
    b.push(KA_LEN);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(&ack.to_be_bytes());
    b.push(ask);
    b.push(flags);
    with_sum(b)
}

pub fn data_bytes(payload: &[u8]) -> Result<Vec<u8>, String> {
    let n = payload.len() + 4;
    if n > 255 {
        return Err("toy data payload is at most 251 bytes".into());
    }
    let mut b = b"DT".to_vec();
    b.push(n as u8);
    b.extend_from_slice(payload);
    Ok(with_sum(b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub struct ToyProtocol {
    pub settings: Map<String, Value>,
    interval: f64,
}

impl ToyProtocol {
    pub fn new(settings: &Map<String, Value>) -> Self {
        let interval = settings.get("keepalive_interval_s").and_then(Value::as_f64).unwrap_or(10.0);
        ToyProtocol { settings: settings.clone(), interval }
    }

    /// Messages back to back by their length byte (offset 2); trailing zeros = padding.
    pub fn split_bytes(data: &[u8]) -> Split {
        let mut parts = vec![];
        let mut o = 0;
        while o < data.len() {
            let rest = &data[o..];
            if rest.iter().all(|b| *b == 0) {
                return Split { parts, padding: rest.len(), problem: String::new() };
            }
            if rest.len() < 4 || rest[2] < 4 || rest[2] as usize > rest.len() {
                parts.push(rest.to_vec());
                return Split { parts, padding: 0, problem: format!("{} bytes at offset {o} do not hold a whole message", rest.len()) };
            }
            let n = rest[2] as usize;
            parts.push(rest[..n].to_vec());
            o += n;
        }
        Split { parts, padding: 0, problem: String::new() }
    }

    pub fn decode_bytes(d: &[u8]) -> Decoded {
        if d.len() < 4 {
            return Decoded::new("unknown", Map::new(), false, vec![format!("short: {} bytes", d.len())], false, None);
        }
        let ok = d[..d.len() - 1].iter().map(|b| *b as u32).sum::<u32>() % 256 == d[d.len() - 1] as u32;
        let problems = if ok { vec![] } else { vec!["bad checksum".to_string()] };
        if &d[..2] == b"KA" && d.len() == KA_LEN as usize {
            let seq = u16::from_be_bytes([d[3], d[4]]) as i64;
            let ack = u16::from_be_bytes([d[5], d[6]]) as i64;
            let fields = json!({"seq": seq, "ack": ack, "ask": d[7], "flags": d[8]});
            return Decoded::new("KeepAlive", fields.as_object().unwrap().clone(), ok, problems, true, Some(seq));
        }
        if &d[..2] == b"DT" {
            let fields = json!({"payload": hex(&d[3..d.len() - 1])});
            return Decoded::new("Data", fields.as_object().unwrap().clone(), ok, problems, false, None);
        }
        Decoded::new("unknown", Map::new(), false, vec!["unknown message tag".into()], false, None)
    }
}

impl Protocol for ToyProtocol {
    fn name(&self) -> &str {
        "toy"
    }
    fn default_port(&self) -> u16 {
        47000
    }
    fn keepalive_interval_s(&self) -> f64 {
        self.interval
    }
    fn keepalive(&mut self, link: &mut LinkState, action: i64) -> HookResult<Vec<u8>> {
        let tx = link.next_tx() as u16;
        Ok(keepalive_bytes(tx, (link.rx_counter & 0xFFFF) as u16, action as u8, 0))
    }
    fn split(&mut self, data: &[u8]) -> Option<HookResult<Split>> {
        Some(Ok(Self::split_bytes(data)))
    }
    fn decode(&mut self, d: &[u8]) -> Decoded {
        Self::decode_bytes(d)
    }
    fn on_receive(&mut self, link: &mut LinkState, msg: &Decoded) -> HookResult<Vec<Vec<u8>>> {
        if msg.ok && msg.is_keepalive && msg.fields.get("ask").and_then(Value::as_i64) == Some(ASK_REPLY as i64) {
            return Ok(vec![self.keepalive(link, 0)?]);
        }
        Ok(vec![])
    }
    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new("ping", "Ping", false, "Send a keepalive now."),
            ActionSpec::new("ask_reply", "Ask for a reply", false, "Ask the peer to reply with a keepalive now."),
        ]
    }
    fn build_action(&mut self, link: &mut LinkState, name: &str, _args: &Map<String, Value>) -> HookResult<Vec<Vec<u8>>> {
        let code = match name {
            "ping" => 0,
            "ask_reply" => ASK_REPLY as i64,
            _ => return Err(format!("'toy: unknown action {}'", crate::pyfmt::str_repr(name))),
        };
        Ok(vec![self.keepalive(link, code)?])
    }
    fn peer_request_field(&self) -> Option<&str> {
        Some("ask")
    }
    fn sim_marker(&self) -> Option<(String, Value)> {
        Some(("flags".into(), json!(SIMULATOR_FLAG)))
    }
}

fn create(settings: &Map<String, Value>) -> Result<Box<dyn Protocol>, String> {
    Ok(Box::new(ToyProtocol::new(settings)))
}

/// The registry entry for `toy`, its simulator and the shipped `sim-local` profile.
pub fn plugin() -> Plugin {
    Plugin {
        name: "toy".into(),
        create,
        validate_session: None,
        simulators: vec![("toy".into(), crate::sim_toy::main)],
        profiles: vec![("sim-local".into(), SIM_LOCAL_PROFILE.into())],
        builtin: true,
        config_aliases: Default::default(),
    }
}
