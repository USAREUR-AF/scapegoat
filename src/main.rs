// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The `scapegoat` binary: the open core with the `toy` protocol.

fn main() {
    scapegoat::protocol::Registry::new().with(scapegoat::toy::plugin()).install();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(scapegoat::run(argv));
}
