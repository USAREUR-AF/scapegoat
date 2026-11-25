// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! SIGTERM and Ctrl-C: a flag the long-running commands watch, so they stop cleanly.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handler(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Install the handlers (once is enough; again is harmless).
pub fn install() {
    unsafe {
        libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
    }
}

pub fn stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// Set `flag` when SIGTERM or SIGINT arrives.
pub fn on_stop(flag: Arc<AtomicBool>) {
    install();
    std::thread::spawn(move || loop {
        if stopped() {
            flag.store(true, Ordering::SeqCst);
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    });
}
