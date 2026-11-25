// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! scapegoat plays the C2 side of a sensor link: it speaks first, keeps the link alive and
//! shows whether the sensor is answering. This crate is the whole program as a library, so a
//! protocol crate can register its protocol and build its own node binary (ADR 0002).
#![recursion_limit = "512"]

pub mod clock;
pub mod config;
pub mod destinations;
pub mod log;
pub mod protocol;
pub mod pyfmt;
pub mod service;
pub mod session;
pub mod signals;
pub mod sim_toy;
pub mod toy;
pub mod traffic;

/// The release version (the VERSION file).
pub const VERSION: &str = include_str!("../VERSION").trim_ascii();

/// The command line with the protocols already registered (`Registry::install`). Returns
/// the exit code.
pub fn run(argv: Vec<String>) -> i32 {
    if argv.first().map(String::as_str) == Some("--version") {
        println!("scapegoat {VERSION}");
        return 0;
    }
    if argv.first().map(String::as_str) == Some("sim") {
        let Some(which) = argv.get(1) else {
            eprintln!("usage: scapegoat sim [-h] which\nscapegoat sim: error: the following arguments are required: which");
            return 2;
        };
        let reg = protocol::Registry::current();
        let sims = reg.simulators();
        return match sims.iter().find(|(s, _, _)| s == which) {
            Some((_, _, main)) => main(argv[2..].to_vec()),
            None => {
                let mut have: Vec<String> = sims.iter().map(|(s, _, _)| s.clone()).collect();
                have.sort();
                let have = if have.is_empty() { "none".to_string() } else { have.join(", ") };
                eprintln!("scapegoat: no simulator {} installed (have: {have})", pyfmt::str_repr(which));
                1
            }
        };
    }
    eprintln!("scapegoat: this command is not ported to the binary yet");
    2
}
