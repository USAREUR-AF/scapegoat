// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Protocol conformance kit.
//!
//! Checks any [`Protocol`] (the built-in `toy` or a plugin crate's) against the contract the
//! core relies on, without knowing anything about the protocol's message layouts. In a
//! plugin crate's tests:
//!
//! ```ignore
//! scapegoat::protocol_conformance!(|| Box::new(MyProtocol::new(&settings)));
//! ```
//!
//! Checks: decode never panics (seeded fuzz, the same samples as the Python kit), a keepalive
//! decodes as a keepalive carrying our sequence number, the sequence number wraps
//! 65535 -> 1, a keepalive echoes the peer's sequence number, every action has a name and label and
//! every non-dangerous action builds bytes, on_receive answers with datagrams, split (when
//! the protocol has one) returns two concatenated keepalives as two messages, summarize
//! returns a line, and every descriptive value is usable.

use crate::protocol::{LinkState, Protocol};
use serde_json::{Map, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const FUZZ_CASES: usize = 400;
pub const FUZZ_SEED: u32 = 20261121;

/// Python's `random.Random(seed)` (MT19937), for the same fuzz samples as the Python kit.
pub struct PyRandom {
    mt: [u32; 624],
    i: usize,
}

impl PyRandom {
    pub fn new(seed: u32) -> PyRandom {
        let mut r = PyRandom { mt: [0; 624], i: 624 };
        r.init_genrand(19650218);
        // init_by_array with key = [seed]
        let key = [seed];
        let (mut i, mut j) = (1usize, 0usize);
        for _ in 0..624usize.max(key.len()) {
            let prev = r.mt[i - 1] ^ (r.mt[i - 1] >> 30);
            r.mt[i] = (r.mt[i] ^ prev.wrapping_mul(1664525)).wrapping_add(key[j]).wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= 624 {
                r.mt[0] = r.mt[623];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
        }
        for _ in 0..623 {
            let prev = r.mt[i - 1] ^ (r.mt[i - 1] >> 30);
            r.mt[i] = (r.mt[i] ^ prev.wrapping_mul(1566083941)).wrapping_sub(i as u32);
            i += 1;
            if i >= 624 {
                r.mt[0] = r.mt[623];
                i = 1;
            }
        }
        r.mt[0] = 0x8000_0000;
        r.i = 624;
        r
    }

    fn init_genrand(&mut self, s: u32) {
        self.mt[0] = s;
        for k in 1..624 {
            self.mt[k] = 1812433253u32.wrapping_mul(self.mt[k - 1] ^ (self.mt[k - 1] >> 30)).wrapping_add(k as u32);
        }
    }

    fn next_u32(&mut self) -> u32 {
        if self.i >= 624 {
            for k in 0..624 {
                let y = (self.mt[k] & 0x8000_0000) | (self.mt[(k + 1) % 624] & 0x7fff_ffff);
                let mut v = self.mt[(k + 397) % 624] ^ (y >> 1);
                if y & 1 != 0 {
                    v ^= 0x9908_b0df;
                }
                self.mt[k] = v;
            }
            self.i = 0;
        }
        let mut y = self.mt[self.i];
        self.i += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        y
    }

    /// `getrandbits(k)` for 1 <= k <= 32.
    pub fn getrandbits(&mut self, k: u32) -> u32 {
        self.next_u32() >> (32 - k)
    }

    /// `randint(a, b)`.
    pub fn randint(&mut self, a: u32, b: u32) -> u32 {
        let n = b - a + 1;
        let k = 32 - n.leading_zeros();
        loop {
            let r = self.getrandbits(k);
            if r < n {
                return a + r;
            }
        }
    }
}

fn none() -> Map<String, Value> {
    Map::new()
}

/// The fuzz samples: fixed edge cases, then FUZZ_CASES random datagrams of 0..300 bytes.
pub fn fuzz_samples() -> Vec<Vec<u8>> {
    let mut rnd = PyRandom::new(FUZZ_SEED);
    let mut s: Vec<Vec<u8>> = vec![vec![], vec![0], vec![0xff; 3], (0..=255u8).collect()];
    for _ in 0..FUZZ_CASES {
        let n = rnd.randint(0, 300);
        s.push((0..n).map(|_| rnd.getrandbits(8) as u8).collect());
    }
    s
}

pub type Make<'a> = &'a dyn Fn() -> Box<dyn Protocol>;

pub fn decode_never_panics(make: Make) -> Result<(), String> {
    let mut p = make();
    let mut samples = fuzz_samples();
    let ka = p.keepalive(&mut LinkState::default(), 0).map_err(|e| format!("keepalive failed: {e}"))?;
    samples.extend((0..ka.len()).map(|i| ka[..i].to_vec()));
    let mut padded = ka.clone();
    padded.extend([0u8; 7]);
    samples.push(padded);
    samples.push(vec![0u8; ka.len()]);
    for d in samples {
        if catch_unwind(AssertUnwindSafe(|| p.decode(&d))).is_err() {
            return Err(format!("decode panicked on {} bytes: {}", d.len(), crate::traffic::hex(&d)));
        }
    }
    Ok(())
}

pub fn keepalive_round_trip(make: Make) -> Result<(), String> {
    let mut p = make();
    let mut link = LinkState::default();
    let ka = p.keepalive(&mut link, 0)?;
    if ka.is_empty() {
        return Err("keepalive() gave no bytes".into());
    }
    if link.tx_counter != 1 {
        return Err("keepalive() must advance the sequence number once".into());
    }
    let msg = p.decode(&ka);
    if !msg.is_keepalive || !msg.ok {
        return Err(format!("a keepalive does not decode as a good keepalive: {:?}", msg.problems));
    }
    if msg.peer_tx_counter != Some(link.tx_counter) {
        return Err(format!("peer_tx_counter {:?}, sent {}", msg.peer_tx_counter, link.tx_counter));
    }
    Ok(())
}

pub fn sequence_wraps_to_one(make: Make) -> Result<(), String> {
    let mut p = make();
    let mut link = LinkState { tx_counter: 65535, ..Default::default() };
    let ka = p.keepalive(&mut link, 0)?;
    let msg = p.decode(&ka);
    if link.tx_counter != 1 || msg.peer_tx_counter != Some(1) {
        return Err(format!("after 65535 the counter is {} and the keepalive says {:?}", link.tx_counter, msg.peer_tx_counter));
    }
    Ok(())
}

pub fn peer_sequence_echoed(make: Make) -> Result<(), String> {
    let mut p = make();
    let mut link = LinkState { rx_counter: 4321, ..Default::default() };
    let ka = p.keepalive(&mut link, 0)?;
    let msg = p.decode(&ka);
    let ints = msg.fields.values().chain(msg.values.values()).filter_map(|v| v.as_i64());
    if !ints.into_iter().any(|v| v == 4321) {
        return Err("a keepalive should carry the last peer sequence number we saw".into());
    }
    Ok(())
}

pub fn actions_are_well_formed(make: Make) -> Result<(), String> {
    let mut p = make();
    for spec in p.actions() {
        if spec.name.is_empty() || spec.label.is_empty() {
            return Err(format!("action {:?} needs a name and a label", spec.name));
        }
        if !spec.dangerous {
            let data = p.build_action(&mut LinkState::default(), &spec.name, &none()).map_err(|e| format!("{}: {e}", spec.name))?;
            if data.is_empty() {
                return Err(format!("{} built no datagram", spec.name));
            }
        }
    }
    Ok(())
}

pub fn on_receive_returns_bytes(make: Make) -> Result<(), String> {
    let mut p = make();
    let ka = p.keepalive(&mut LinkState::default(), 0)?;
    let msg = p.decode(&ka);
    p.on_receive(&mut LinkState::default(), &msg).map(|_| ())
}

/// Ok(false) when the protocol has no split.
pub fn split_two_keepalives(make: Make) -> Result<bool, String> {
    let mut p = make();
    let a = p.keepalive(&mut LinkState::default(), 0)?;
    let b = p.keepalive(&mut LinkState { tx_counter: 7, ..Default::default() }, 0)?;
    let both = [a.clone(), b.clone()].concat();
    match p.split(&both) {
        None => Ok(false),
        Some(r) => {
            let s = r?;
            if s.parts != vec![a, b] {
                return Err(format!("split gave {} parts, not the two keepalives", s.parts.len()));
            }
            Ok(true)
        }
    }
}

pub fn hook_types(make: Make) -> Result<(), String> {
    let mut p = make();
    if p.transmit_actions().iter().any(|a| a.is_empty()) {
        return Err("transmit_actions holds an empty name".into());
    }
    let ka = p.keepalive(&mut LinkState::default(), 0)?;
    let msg = p.decode(&ka);
    p.summarize(&msg)?;
    if p.keepalive_interval_s() <= 0.0 {
        return Err("keepalive_interval_s must be above 0".into());
    }
    Ok(())
}

/// Generate one test per conformance check for the protocol `make` builds.
#[macro_export]
macro_rules! protocol_conformance {
    ($make:expr) => {
        fn conformance_make() -> Box<dyn $crate::protocol::Protocol> {
            ($make)()
        }
        #[test]
        fn test_decode_never_raises() {
            $crate::conformance::decode_never_panics(&conformance_make).unwrap();
        }
        #[test]
        fn test_keepalive_round_trip() {
            $crate::conformance::keepalive_round_trip(&conformance_make).unwrap();
        }
        #[test]
        fn test_sequence_wraps_to_one() {
            $crate::conformance::sequence_wraps_to_one(&conformance_make).unwrap();
        }
        #[test]
        fn test_peer_sequence_echoed() {
            $crate::conformance::peer_sequence_echoed(&conformance_make).unwrap();
        }
        #[test]
        fn test_actions_are_well_formed() {
            $crate::conformance::actions_are_well_formed(&conformance_make).unwrap();
        }
        #[test]
        fn test_on_receive_returns_bytes() {
            $crate::conformance::on_receive_returns_bytes(&conformance_make).unwrap();
        }
        #[test]
        fn test_split_two_keepalives() {
            if !$crate::conformance::split_two_keepalives(&conformance_make).unwrap() {
                eprintln!("skipped: protocol has no split()");
            }
        }
        #[test]
        fn test_hook_types() {
            $crate::conformance::hook_types(&conformance_make).unwrap();
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_numbers_as_python() {
        // python3 -c "import random; r=random.Random(20261121); print([r.randint(0,300) for _ in range(3)], [r.getrandbits(8) for _ in range(3)])"
        let mut r = PyRandom::new(20261121);
        let a: Vec<u32> = (0..3).map(|_| r.randint(0, 300)).collect();
        let b: Vec<u32> = (0..3).map(|_| r.getrandbits(8)).collect();
        assert_eq!((a, b), (vec![269, 89, 143], vec![89, 202, 155]));
    }

    #[test]
    fn same_fuzz_samples_as_python() {
        // FNV-1a 64 over the 400 random samples the Python kit builds.
        let all: Vec<u8> = fuzz_samples()[4..].concat();
        let h = all.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x0100_0000_01b3));
        assert_eq!((all.len(), h), (57933, 0x149f_726b_0ff1_eb5c));
    }
}
