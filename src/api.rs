// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! The JSON API and the web page, on the same routes, methods, status codes and JSON as
//! the Python version (`scapegoat/api/http.py`).

use crate::http::{parse_qs, Request, Response, Server};
use crate::pyfmt;
use crate::service::{NetError, Service};
use crate::session::{ActionError, Session};
use serde_json::{json, Map, Value};
use std::sync::Arc;

/// The web page, built into the binary.
pub const UI: &[u8] = include_bytes!("../ui/index.html");
/// Read-only network probes (scapegoat net ping / capture / udp_probe).
pub const PROBE_ACTIONS: [&str; 3] = ["ping", "capture", "udp_probe"];

pub struct ApiError(pub u16, pub String);

impl From<ActionError> for ApiError {
    fn from(e: ActionError) -> Self {
        ApiError(e.status(), e.message().to_string())
    }
}

enum Body {
    Json(Value),
    Html(&'static [u8]),
}

type R = Result<(u16, Body), ApiError>;

fn source(req: &Request) -> String {
    let src = crate::extension::current().header(|n| req.header(n), "X-Scapegoat-Source");
    let src = if src.is_empty() { "api".to_string() } else { src.trim().to_lowercase() };
    if ["cli", "ui", "api"].contains(&src.as_str()) {
        src
    } else {
        "api".into()
    }
}

/// Who/where for the audit trail: the CLI's user name, else the client address.
fn who(req: &Request) -> String {
    let user: String = crate::extension::current().header(|n| req.header(n), "X-Scapegoat-User").trim().chars().take(64).collect();
    let addr = req.client.ip().to_string();
    if user.is_empty() {
        addr
    } else {
        format!("{user}@{addr}")
    }
}

fn body(req: &Request) -> Result<Map<String, Value>, ApiError> {
    if req.too_large {
        return Err(ApiError(400, "request body too large".into()));
    }
    if req.body.is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_slice::<Value>(&req.body) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err(ApiError(400, "request body must be a JSON object".into())),
        Err(_) => Err(ApiError(400, "request body must be JSON".into())),
    }
}

fn session<'a>(svc: &'a Service, sid: &str) -> Result<&'a Session, ApiError> {
    svc.session(sid).ok_or_else(|| {
        let known = svc.session_ids();
        ApiError(
            404,
            format!(
                "no session named {}. Known: {}",
                pyfmt::str_repr(sid),
                if known.is_empty() { "none".into() } else { known.join(", ") }
            ),
        )
    })
}

fn q<'a>(query: &'a [(String, String)], k: &str) -> Option<&'a str> {
    query.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
}

fn py_float(s: &str) -> Option<f64> {
    let t = s.trim().to_lowercase();
    if t.is_empty() || t.contains("_") && (t.starts_with('_') || t.ends_with('_')) {
        return None;
    }
    t.replace('_', "").parse::<f64>().ok()
}

fn iface_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 15 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

/// `/api/sessions/<sid>/<rest>` -> (sid, [rest segments]); segments are never empty.
fn split_session_path(path: &str) -> Option<(String, Vec<String>)> {
    let rest = path.strip_prefix("/api/sessions/")?;
    let segs: Vec<&str> = rest.split('/').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return None;
    }
    Some((segs[0].to_string(), segs[1..].iter().map(|s| s.to_string()).collect()))
}

fn ok(v: Value) -> R {
    Ok((200, Body::Json(v)))
}

fn route(svc: &Service, req: &Request, method: &str, path: &str, query: &[(String, String)]) -> R {
    if method == "GET" && (path == "/" || path == "/index.html") {
        return Ok((200, Body::Html(UI)));
    }
    if method == "GET" && path == "/api/health" {
        return ok(svc.health());
    }
    if method == "GET" && path == "/api/sessions" {
        return ok(Value::Array(svc.sessions.iter().map(|s| s.status(0)).collect()));
    }
    if let Some((sid, segs)) = split_session_path(path) {
        let seg: Vec<&str> = segs.iter().map(String::as_str).collect();
        match (method, seg.as_slice()) {
            ("GET", []) => return ok(session(svc, &sid)?.status(50)),
            ("GET", ["events"]) => {
                let n = match q(query, "n") {
                    None => 200,
                    Some(v) => crate::config::py_int(v).ok_or_else(|| ApiError(400, "n must be a number".into()))?,
                };
                return ok(Value::Array(session(svc, &sid)?.get_events(n)));
            }
            ("GET", ["traffic"]) => {
                let s = session(svc, &sid)?;
                let bad = || ApiError(400, "since and limit must be numbers".into());
                let since = match q(query, "since") {
                    None => None,
                    Some(v) => Some(crate::config::py_int(v).ok_or_else(bad)?),
                };
                let limit = match q(query, "limit") {
                    None => 200,
                    Some(v) => crate::config::py_int(v).ok_or_else(bad)?,
                };
                return ok(s.get_traffic(since, limit));
            }
            ("GET", ["wire"]) => {
                let s = session(svc, &sid)?;
                let seconds = match q(query, "seconds") {
                    None => 10.0,
                    Some(v) => py_float(v).ok_or_else(|| ApiError(400, "seconds must be a number".into()))?,
                };
                let iface = q(query, "iface").unwrap_or("any").to_string();
                if !iface_ok(&iface) {
                    return Err(ApiError(400, "bad interface name".into()));
                }
                let port = s.with(|i| i.local.1);
                svc.event("wire", &format!("wire capture {}s on {} port {port}", pyfmt::g(seconds), s.id), "info", &source(req));
                return ok(s.wire(seconds, &iface));
            }
            ("POST", ["actions", name]) => {
                let b = body(req)?;
                let s = session(svc, &sid)?;
                let args = match b.get("args") {
                    None | Some(Value::Null) => Map::new(),
                    Some(Value::Object(m)) => m.clone(),
                    Some(v) if !crate::config::truthy(Some(v)) => Map::new(),
                    Some(_) => return Err(ApiError(400, "args must be an object".into())),
                };
                let confirm = b.get("confirm").cloned().unwrap_or(Value::Null);
                let token = b.get("token").and_then(Value::as_str);
                return ok(s.run_action(&name.replace('-', "_"), &confirm, &source(req), &args, token, &who(req))?);
            }
            ("POST", [what @ ("arm" | "disarm"), name]) => {
                let b = body(req)?;
                let s = session(svc, &sid)?;
                let name = name.replace('-', "_");
                if *what == "arm" {
                    let args = b.get("args").and_then(Value::as_object).cloned().unwrap_or_default();
                    return ok(s.arm(&name, &source(req), &who(req), &args)?);
                }
                return ok(s.disarm(&name, &source(req), &who(req)));
            }
            ("POST", [cmd @ ("enable" | "disable" | "reset")]) => {
                body(req)?;
                let s = session(svc, &sid)?;
                let src = source(req);
                match *cmd {
                    "enable" => s.enable(&src)?,
                    "disable" => s.disable(&src),
                    _ => s.reset(&src),
                }
                return ok(s.status(0));
            }
            ("POST", ["lock"]) => {
                let b = body(req)?;
                let s = session(svc, &sid)?;
                if !crate::config::truthy(b.get("peer")) {
                    return Err(ApiError(400, "give the address to lock onto: {\"peer\": \"IP:PORT\"}".into()));
                }
                s.force_lock(&pyfmt::str(&b["peer"]), &source(req))?;
                return ok(s.status(0));
            }
            _ => {}
        }
    }
    if method == "GET" && path == "/api/outputs" {
        return ok(svc.outputs.status());
    }
    if method == "GET" && path == "/api/node" {
        let lo = ["1", "true", "yes"].contains(&q(query, "loopback").unwrap_or("0"));
        return ok(crate::node::snapshot(&svc.cfg(), lo));
    }
    if method == "GET" && path == "/api/profiles" {
        let dir = svc.cfg().get_str("profiles_dir");
        return ok(Value::Array(crate::config::list_profiles(dir.as_deref())));
    }
    if method == "GET" && path == "/api/events" {
        return ok(Value::Array(svc.events_list()));
    }
    if method == "GET" && path == "/api/net" {
        return match svc.net_snapshot() {
            Ok(v) => ok(v),
            Err(NetError::Unavailable(m)) => Err(ApiError(501, m)),
            Err(NetError::Permission(m)) => Err(ApiError(403, m)),
            Err(NetError::Invalid(m)) => Err(ApiError(400, m)),
        };
    }
    if let Some(name) = path.strip_prefix("/api/net/") {
        if method == "POST" && !name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
            let b = body(req)?;
            return net_action(svc, req, name, b);
        }
    }
    Err(ApiError(404, format!("no such endpoint: {method} {path}")))
}

fn net_action(svc: &Service, req: &Request, name: &str, b: Map<String, Value>) -> R {
    let src = source(req);
    if PROBE_ACTIONS.contains(&name) {
        svc.event("net", &format!("net {name} {}", pyfmt::dumps_sorted(&Value::Object(b.clone()))), "info", &src);
        return match svc.net_probe(name, &b) {
            Ok(v) => ok(v),
            Err(NetError::Unavailable(m)) => Err(ApiError(501, m)),
            Err(NetError::Invalid(m)) | Err(NetError::Permission(m)) => Err(ApiError(400, format!("{name}: {m}"))),
        };
    }
    if !svc.cfg().allow_net_control {
        svc.event("refused", &format!("net {name} refused: allow_net_control is false"), "warn", &src);
        return Err(ApiError(
            403,
            "network control is off. Set allow_net_control = true in the config and restart scapegoat, then repeat with confirm.".into(),
        ));
    }
    if b.get("confirm") != Some(&Value::Bool(true)) {
        svc.event("refused", &format!("net {name} refused: not confirmed"), "warn", &src);
        return Err(ApiError(403, format!("net {name} changes the node's network: repeat it with confirm (--confirm on the CLI).")));
    }
    let result = match svc.net_run(name, &b, &src) {
        Ok(v) => v,
        Err(NetError::Unavailable(m)) => return Err(ApiError(501, m)),
        Err(NetError::Permission(m)) => return Err(ApiError(403, m)),
        Err(NetError::Invalid(m)) => return Err(ApiError(400, format!("net {name}: {m}"))),
    };
    if result.get("ok") == Some(&Value::Bool(false)) {
        let msg = [result.get("error"), result.get("message")]
            .into_iter()
            .flatten()
            .find(|v| crate::config::truthy(Some(v)))
            .map(pyfmt::str)
            .unwrap_or_else(|| format!("net {name} failed"));
        let mut r = result.clone();
        r["error"] = json!(msg);
        return Ok((if msg.starts_with("refused") { 403 } else { 400 }, Body::Json(r)));
    }
    ok(result)
}

/// Answer one request.
pub fn handle(svc: &Service, req: &Request) -> Response {
    if req.method != "GET" && req.method != "POST" {
        let text = format!(
            "<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n        <title>Error response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n        <p>Error code: 501</p>\n        <p>Message: Unsupported method ({}).</p>\n        <p>Error code explanation: 501 - Server does not support this operation.</p>\n    </body>\n</html>\n",
            pyfmt::str_repr(&req.method)
        );
        return Response { status: 501, content_type: "text/html;charset=utf-8".into(), body: text.into_bytes() };
    }
    let (p, qs) = req.target.split_once('?').unwrap_or((&req.target, ""));
    let p = p.split('#').next().unwrap_or("");
    let path = match p.trim_end_matches('/') {
        "" => "/",
        x => x,
    };
    let query = parse_qs(qs);
    let (status, b) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| route(svc, req, &req.method, path, &query))) {
        Ok(Ok(x)) => x,
        Ok(Err(ApiError(code, msg))) => (code, Body::Json(json!({"error": msg}))),
        Err(_) => {
            crate::log::error("scapegoat.api", &format!("API error on {} {}", req.method, req.target));
            (500, Body::Json(json!({"error": "internal error"})))
        }
    };
    match b {
        Body::Html(bytes) => Response { status, content_type: "text/html; charset=utf-8".into(), body: bytes.to_vec() },
        Body::Json(v) => Response { status, content_type: "application/json".into(), body: pyfmt::dumps(&v).into_bytes() },
    }
}

/// Serve the API on `bind` for `svc`.
pub fn serve(svc: Arc<Service>, bind: &str) -> std::io::Result<Server> {
    Server::bind(bind, Arc::new(move |req: &Request| handle(&svc, req)))
}
