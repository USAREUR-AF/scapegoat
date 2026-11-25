// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The Rust form of the Python suite in tests/. Each module names the Python file it covers;
//! each test keeps the Python test's name.

mod api;
mod cli;
mod core;
mod forward;
mod latch;
mod net;
mod node;
mod outputs;
mod support;
mod traffic;
