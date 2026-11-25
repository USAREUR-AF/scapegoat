// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Monotonic seconds (for timers) and wall time (for what people read), as floats.

use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

static START: OnceLock<Instant> = OnceLock::new();

/// Seconds on a monotonic clock. Starts at 1000 so that "0 = never" never collides.
pub fn mono() -> f64 {
    let start = START.get_or_init(Instant::now);
    1000.0 + start.elapsed().as_secs_f64()
}

/// Seconds since the Unix epoch.
pub fn wall() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// (year, month, day, hour, minute, second, microsecond) in UTC.
pub fn civil(ts: f64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let secs = ts.floor() as i64;
    let micros = ((ts - secs as f64) * 1_000_000.0).floor() as u32;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60, micros.min(999_999))
}

/// `2026-11-21T11:00:50.099Z` (milliseconds, truncated as `strftime("%f")[:-3]`).
pub fn iso_ms(ts: f64) -> String {
    let (y, mo, d, h, mi, s, us) = civil(ts);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}Z", us / 1000)
}

/// `2026-11-21T11:00:50Z`.
pub fn iso_s(ts: f64) -> String {
    let (y, mo, d, h, mi, s, _) = civil(ts);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `11:00:50` in UTC.
pub fn hhmmss(ts: f64) -> String {
    let (_, _, _, h, mi, s, _) = civil(ts);
    format!("{h:02}:{mi:02}:{s:02}")
}

pub fn now_iso() -> String {
    iso_ms(wall())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso() {
        assert_eq!(iso_ms(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_ms(1_795_000_850.099_5), "2026-11-18T11:20:50.099Z");
        assert_eq!(iso_s(951_782_400.0), "2000-02-29T00:00:00Z");
        assert_eq!(hhmmss(3_725.0), "01:02:05");
    }
}
