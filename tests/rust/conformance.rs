// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_conformance_toy.py: the conformance kit against the open toy protocol (the
//! kit's own self-test).

scapegoat::protocol_conformance!(|| scapegoat::protocol::load_protocol("toy", &serde_json::Map::new()).unwrap());
