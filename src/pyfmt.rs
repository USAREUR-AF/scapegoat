// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Text exactly as the Python version printed it: `str()`, `repr()`, float repr, `%g`, and
//! `json.dumps` (ASCII only, `", "` and `": "` separators, or `indent=2`). The API's JSON,
//! the CLI's text and every message quoting a value keep their earlier form.

use serde_json::{Map, Value};
use std::fmt::Write;

/// Python `repr(float)`: the shortest text that reads back as the same number, with an
/// exponent below 1e-4 and from 1e16.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    // Rust's {:e} gives the shortest round-trip digits: "1.2345e-5", "1e16".
    let e = format!("{:e}", f);
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    let sign = if neg { "-" } else { "" };
    if !(-4..16).contains(&exp) {
        let m = if digits.len() > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits.clone() };
        let es = if exp < 0 { "-" } else { "+" };
        return format!("{sign}{m}e{es}{:02}", exp.abs());
    }
    let n = digits.len() as i32;
    let s = if exp >= 0 {
        if n - 1 <= exp {
            format!("{}{}.0", digits, "0".repeat((exp - (n - 1)) as usize))
        } else {
            let p = (exp + 1) as usize;
            format!("{}.{}", &digits[..p], &digits[p..])
        }
    } else {
        format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
    };
    format!("{sign}{s}")
}

/// Python `format(x, "g")` (six significant digits).
pub fn g(f: f64) -> String {
    gp(f, 6)
}

/// Python `format(x, ".<p>g")`.
pub fn gp(f: f64, p: usize) -> String {
    if f.is_nan() {
        return "nan".into();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let p = p.max(1);
    let e = format!("{:.*e}", p - 1, f);
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    if exp < -4 || exp >= p as i32 {
        let m = strip_zeros(mant);
        let es = if exp < 0 { "-" } else { "+" };
        format!("{m}e{es}{:02}", exp.abs())
    } else {
        let decimals = (p as i32 - 1 - exp).max(0) as usize;
        strip_zeros(&format!("{:.*}", decimals, f))
    }
}

fn strip_zeros(s: &str) -> String {
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s.to_string()
    }
}

/// Python `repr(str)`.
pub fn str_repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// Python `repr()` of a JSON-shaped value.
pub fn repr(v: &Value) -> String {
    match v {
        Value::String(s) => str_repr(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(m) => {
            format!("{{{}}}", m.iter().map(|(k, v)| format!("{}: {}", str_repr(k), repr(v))).collect::<Vec<_>>().join(", "))
        }
        other => str(other),
    }
}

/// Python `str()` of a JSON-shaped value.
pub fn str(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if n.is_f64() {
                float_repr(n.as_f64().unwrap())
            } else {
                n.to_string()
            }
        }
        Value::String(s) => s.clone(),
        other => repr(other),
    }
}

/// The first `n` characters (Python `s[:n]`).
pub fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `json.dumps(v)`: one line, `", "` and `": "`, ASCII only.
pub fn dumps(v: &Value) -> String {
    let mut out = String::new();
    write_json(&mut out, v, None, 0);
    out
}

/// `json.dumps(v, indent=2)`.
pub fn dumps_indent(v: &Value, indent: usize) -> String {
    let mut out = String::new();
    write_json(&mut out, v, Some(indent), 0);
    out
}

/// `json.dumps(v, sort_keys=True)`.
pub fn dumps_sorted(v: &Value) -> String {
    dumps(&sort_keys(v))
}

fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), sort_keys(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{:04x}", u);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_json(out: &mut String, v: &Value, indent: Option<usize>, level: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_f64() {
                let f = n.as_f64().unwrap();
                if f.is_nan() {
                    out.push_str("NaN");
                } else if f.is_infinite() {
                    out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" });
                } else {
                    out.push_str(&float_repr(f));
                }
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_none() {
                        out.push(' ');
                    }
                }
                if let Some(n) = indent {
                    out.push('\n');
                    out.push_str(&" ".repeat(n * (level + 1)));
                }
                write_json(out, x, indent, level + 1);
            }
            if let Some(n) = indent {
                out.push('\n');
                out.push_str(&" ".repeat(n * level));
            }
            out.push(']');
        }
        Value::Object(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    if indent.is_none() {
                        out.push(' ');
                    }
                }
                if let Some(n) = indent {
                    out.push('\n');
                    out.push_str(&" ".repeat(n * (level + 1)));
                }
                write_str(out, k);
                out.push_str(": ");
                write_json(out, x, indent, level + 1);
            }
            if let Some(n) = indent {
                out.push('\n');
                out.push_str(&" ".repeat(n * level));
            }
            out.push('}');
        }
    }
}

/// An OS error as Python prints it: `[Errno 98] Address already in use`.
pub fn os_error(e: &std::io::Error) -> String {
    if let Some(code) = e.raw_os_error() {
        let text = e.to_string();
        let msg = text.split(" (os error").next().unwrap_or(&text).to_string();
        format!("[Errno {code}] {msg}")
    } else if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        "timed out".into()
    } else {
        e.to_string()
    }
}

/// Python `round(x, n)` for the ages and windows the status shows.
pub fn round(x: f64, n: i32) -> f64 {
    let m = 10f64.powi(n);
    let y = x * m;
    let r = y.round();
    // Python rounds half to even.
    let r = if (y - y.trunc()).abs() == 0.5 { 2.0 * (y / 2.0).round() } else { r };
    r / m
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_like_python() {
        for (f, want) in [
            (3.0, "3.0"),
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (123.456, "123.456"),
            (-2.5, "-2.5"),
            (1.5e-7, "1.5e-07"),
        ] {
            assert_eq!(float_repr(f), want, "{f}");
        }
        assert_eq!(g(10.0), "10");
        assert_eq!(g(0.2), "0.2");
        assert_eq!(g(5.0), "5");
        assert_eq!(g(1234567.0), "1.23457e+06");
    }

    #[test]
    fn json_like_python() {
        let v = json!({"a": [1, 2.0, "x·"], "b": {}, "c": [], "d": null});
        assert_eq!(dumps(&v), "{\"a\": [1, 2.0, \"x\\u00b7\"], \"b\": {}, \"c\": [], \"d\": null}");
        assert_eq!(dumps_indent(&json!({"a": [1]}), 2), "{\n  \"a\": [\n    1\n  ]\n}");
        assert_eq!(repr(&json!("it's")), "\"it's\"");
        assert_eq!(repr(&json!(["a", 1, true, null])), "['a', 1, True, None]");
    }
}
