// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The service log on stderr: `2026-11-25 20:34:01,123 INFO scapegoat.session: ...`.
//! Off until `init` is called (as Python's loggers were until `serve` configured them).

use std::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Level {
    Debug = 1,
    Info = 2,
    Warning = 3,
    Error = 4,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
        }
    }
}

/// Log at `level` and above.
pub fn init(level: Level) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    let l = LEVEL.load(Ordering::Relaxed);
    l != 0 && level as u8 >= l
}

fn local_time() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as libc::time_t;
    let ms = now.subsec_millis();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe {
        libc::localtime_r(&secs, &mut tm);
    }
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms)
}

pub fn log(level: Level, name: &str, msg: &str) {
    if enabled(level) {
        eprintln!("{} {} {}: {}", local_time(), level.name(), name, msg);
    }
}

pub fn info(name: &str, msg: &str) {
    log(Level::Info, name, msg)
}

pub fn warning(name: &str, msg: &str) {
    log(Level::Warning, name, msg)
}

pub fn error(name: &str, msg: &str) {
    log(Level::Error, name, msg)
}
