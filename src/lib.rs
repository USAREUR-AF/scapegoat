// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! scapegoat plays the C2 side of a sensor link: it speaks first, keeps the link alive and
//! shows whether the sensor is answering. This crate is the whole program as a library, so a
//! protocol crate can register its protocol and build its own node binary (ADR 0002).
#![recursion_limit = "512"]

pub mod api;
pub mod cli;
pub mod clock;
pub mod config;
pub mod conformance;
pub mod destinations;
pub mod extension;
pub mod http;
pub mod ipnet;
pub mod log;
pub mod net;
pub mod node;
pub mod outputs;
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
    cli::main(argv)
}
