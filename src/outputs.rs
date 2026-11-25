// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! C2 outputs: tracks a protocol yields, re-published in standard formats.
//!
//! A protocol turns its sensor's messages into normalized tracks (the `tracks` hook). This
//! module turns each track into a canonical track (canonical-track-v2) and, for every enabled
//! output, encodes it with goat-transformers (ASTERIX CAT062, CoT XML, SAPIENT) and sends it to
//! that output's destinations:
//!
//! ```text
//! udp://host:port            unicast or multicast (224.0.0.0/4) datagram
//! zenoh:<key expression>     HTTP PUT to the Zenoh REST plugin at `island_rest`
//! ```
//!
//! No format is hand-encoded here: the goat-transformers engine (linked in) and its published
//! packs (read from the goat-transformers tree) do the encoding. Without the packs the outputs
//! are off and status says why.

use crate::clock;
use crate::destinations::{parse_destination, Destination};
use crate::protocol::Track;
use crate::pyfmt;
use serde_json::{json, Map, Value};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const CANONICAL: &str = "canonical-track-v2";
/// Formats, and whether the engine's wire text is hex.
pub const FORMATS: [(&str, bool); 3] = [("asterix-cat062", true), ("sapient", true), ("cot-xml", false)];
pub const TRANSFORMERS_DIRS: [&str; 2] = ["/opt/goat-transformers", "/usr/share/goat-transformers"];

// WGS-84
const A: f64 = 6378137.0;
const F: f64 = 1.0 / 298.257223563;
const E2: f64 = F * (2.0 - F);

/// ECEF metres -> (latitude deg, longitude deg, height above the WGS-84 ellipsoid m).
pub fn ecef_to_geodetic(x: f64, y: f64, z: f64) -> (f64, f64, f64) {
    let lon = y.atan2(x);
    let p = x.hypot(y);
    let mut lat = z.atan2(p * (1.0 - E2));
    let mut h = 0.0;
    for _ in 0..10 {
        let n = A / (1.0 - E2 * lat.sin().powi(2)).sqrt();
        h = if lat.cos().abs() > 1e-12 { p / lat.cos() - n } else { z.abs() - n * (1.0 - E2) };
        let new = z.atan2(p * (1.0 - E2 * n / (n + h)));
        if (new - lat).abs() < 1e-13 {
            lat = new;
            break;
        }
        lat = new;
    }
    (lat.to_degrees(), lon.to_degrees(), h)
}

pub fn geodetic_to_ecef(lat_deg: f64, lon_deg: f64, h: f64) -> (f64, f64, f64) {
    let (lat, lon) = (lat_deg.to_radians(), lon_deg.to_radians());
    let n = A / (1.0 - E2 * lat.sin().powi(2)).sqrt();
    ((n + h) * lat.cos() * lon.cos(), (n + h) * lat.cos() * lon.sin(), (n * (1.0 - E2) + h) * lat.sin())
}

/// ECEF velocity -> (east, north, up) m/s at the given position.
pub fn ecef_velocity_to_enu(vx: f64, vy: f64, vz: f64, lat_deg: f64, lon_deg: f64) -> (f64, f64, f64) {
    let (lat, lon) = (lat_deg.to_radians(), lon_deg.to_radians());
    let (sl, cl, so, co) = (lat.sin(), lat.cos(), lon.sin(), lon.cos());
    (-so * vx + co * vy, -sl * co * vx - sl * so * vy + cl * vz, cl * co * vx + cl * so * vy + sl * vz)
}

/// Python `float(v)`.
fn num(t: &Track, k: &str) -> Result<f64, String> {
    match t.get(k) {
        None => Err(format!("'{k}'")),
        Some(Value::Number(n)) => Ok(n.as_f64().unwrap_or(0.0)),
        Some(Value::Bool(b)) => Ok(*b as i64 as f64),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| format!("could not convert string to float: {}", pyfmt::str_repr(s))),
        Some(v) => Err(format!("float() argument must be a string or a real number, not {}", pyfmt::repr(v))),
    }
}

fn present(t: &Track, k: &str) -> bool {
    t.get(k).is_some_and(|v| !v.is_null())
}

/// A normalized track -> a canonical-track-v2 object.
pub fn canonical_track(t: &Track) -> Result<Value, String> {
    let ts = num(t, "time")?;
    let ms = ((ts.rem_euclid(1.0)) * 1000.0).round() as i64 % 1000;
    let (y, mo, d, h, mi, s, _) = clock::civil(ts);
    let obs = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z");
    let tid = t.get("track_id").ok_or("'track_id'")?;
    let src = if crate::config::truthy(t.get("source_id")) { pyfmt::str(&t["source_id"]) } else { "scapegoat".into() };
    let gen = if crate::config::truthy(t.get("generation")) { pyfmt::str(&t["generation"]) } else { "scapegoat-1".into() };
    let flag = |k: &str, d: bool| t.get(k).map(|v| crate::config::truthy(Some(v))).unwrap_or(d);
    let mut out = json!({
        "apiVersion": "billie.dev/track-v2", "kind": "Track",
        "trackId": pyfmt::str(tid), "sourceId": src, "trackGeneration": gen,
        "testData": false, "headerSimulated": false,
        "simulated": flag("simulated", false), "confirmed": flag("confirmed", true),
        "coasting": flag("coasting", false), "finalUpdate": flag("final", false),
        "observedAt": obs,
        "position": {"latitudeDeg": num(t, "lat")?, "longitudeDeg": num(t, "lon")?},
    });
    if present(t, "hae") {
        out["position"]["altitudeM"] = json!(num(t, "hae")?);
    }
    let mut vel = Map::new();
    for (k, s) in [("eastMps", "vel_east"), ("northMps", "vel_north"), ("upMps", "vel_up")] {
        if present(t, s) {
            vel.insert(k.into(), json!(num(t, s)?));
        }
    }
    if !vel.is_empty() {
        out["velocity"] = Value::Object(vel);
    }
    if crate::config::truthy(t.get("classification")) {
        out["classification"] = json!(pyfmt::str(&t["classification"]));
    }
    Ok(out)
}

// ---------------------------------------------------------------- encoder
/// A goat-transformers tree holding packs and model: `path`, else the first of `search`.
pub fn find_transformers_in(path: Option<&str>, search: &[String]) -> Result<String, String> {
    let mut cands: Vec<String> = path.map(|p| vec![p.to_string()]).unwrap_or_default();
    cands.extend(search.iter().cloned());
    for c in &cands {
        let p = std::path::Path::new(c);
        if !c.is_empty() && p.join("packs").is_dir() && p.join("model").is_dir() {
            return Ok(c.clone());
        }
    }
    Err(format!(
        "goat-transformers not found (set [transformers] path, or GOAT_TRANSFORMERS_PATH, to a checkout of USAREUR-AF/goat-transformers; looked in {})",
        cands.iter().filter(|c| !c.is_empty()).cloned().collect::<Vec<_>>().join(", ")
    ))
}

/// Where goat-transformers is looked for after `[transformers] path`: $GOAT_TRANSFORMERS_PATH,
/// then the system directories.
pub fn default_search() -> Vec<String> {
    let mut v = vec![std::env::var("GOAT_TRANSFORMERS_PATH").unwrap_or_default()];
    v.extend(TRANSFORMERS_DIRS.iter().map(|d| d.to_string()));
    v
}

pub fn find_transformers(path: Option<&str>) -> Result<String, String> {
    find_transformers_in(path, &default_search())
}

fn is_hex(fmt: &str) -> bool {
    FORMATS.iter().any(|(f, h)| *f == fmt && *h)
}

/// The goat-transformers engine with the canonical track pack and the output packs.
pub struct Encoder {
    engine: Mutex<goat_transformers::Engine>,
    pub root: String,
}

impl Encoder {
    pub fn new(root: &str, formats: &[String]) -> Result<Encoder, String> {
        let mut eng = goat_transformers::Engine::new();
        eng.load_model_dir(&std::path::Path::new(root).join("model")).map_err(|e| format!("goat-transformers model not loadable: {e}"))?;
        let mut fmts: Vec<String> = formats.to_vec();
        fmts.sort();
        fmts.dedup();
        for fmt in std::iter::once(CANONICAL.to_string()).chain(fmts) {
            let def = std::path::Path::new(root).join("packs").join(&fmt).join("pack.def");
            let text =
                std::fs::read_to_string(&def).map_err(|_| format!("goat-transformers has no pack {} in {root}", pyfmt::str_repr(&fmt)))?;
            eng.load_def(&text).map_err(|e| format!("goat-transformers pack {fmt}: {e}"))?;
        }
        Ok(Encoder { engine: Mutex::new(eng), root: root.into() })
    }

    pub fn encode(&self, fmt: &str, track: &Value, context: &Map<String, Value>) -> Result<Vec<u8>, String> {
        let ctx: Vec<(String, String)> = context.iter().map(|(k, v)| (k.clone(), pyfmt::str(v))).collect();
        let out = self
            .engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .convert_text(CANONICAL, fmt, &pyfmt::dumps(track), Some(&ctx))
            .map_err(|e| e.to_string())?;
        if is_hex(fmt) {
            crate::traffic::unhex(&out).ok_or_else(|| "the encoder gave text that is not hex".to_string())
        } else {
            Ok(out.into_bytes())
        }
    }

    /// Fields of an encoded message (for tests and checks).
    pub fn decode(&self, fmt: &str, data: &[u8]) -> Result<Map<String, Value>, String> {
        let text = if is_hex(fmt) { crate::traffic::hex(data) } else { String::from_utf8_lossy(data).to_string() };
        let ent = self.engine.lock().unwrap_or_else(|e| e.into_inner()).decode(fmt, &text).map_err(|e| e.to_string())?;
        Ok(ent
            .fields
            .iter()
            .map(|(k, v)| {
                let j = match v {
                    goat_transformers::Value::Str(s) => json!(s),
                    goat_transformers::Value::F64(f) => json!(f),
                    goat_transformers::Value::I64(n) => json!(n),
                    #[allow(unreachable_patterns)]
                    other => json!(format!("{other:?}")),
                };
                (k.clone(), j)
            })
            .collect())
    }
}

// ---------------------------------------------------------------- outputs
/// One queued Zenoh REST put: (key, body).
type Put = (String, Vec<u8>);

#[derive(Default)]
struct Counters {
    sent: u64,
    errors: u64,
    last_error: String,
    last_sent: Option<f64>,
    dropped: u64,
    sock: Option<UdpSocket>,
}

pub struct Output {
    pub name: String,
    pub format: String,
    pub enabled: bool,
    pub sessions: Vec<String>,
    pub dests: Vec<Destination>,
    pub ttl: u32,
    pub context: Map<String, Value>,
    pub stale_s: f64,
    /// CAT062 needs the numeric track number; CoT/SAPIENT ids get a prefix so tracks of
    /// different sensors stay apart (default: "<source id>-").
    pub uid_prefix: Option<String>,
    pub island_rest: String,
    c: Mutex<Counters>,
    tx: SyncSender<Put>,
    rx: Mutex<Option<Receiver<Put>>>,
}

impl Output {
    fn new(name: &str, spec: &Value, island_rest: &str) -> Output {
        let (tx, rx) = sync_channel(1000);
        Output {
            name: name.into(),
            format: spec["format"].as_str().unwrap_or("").into(),
            enabled: spec.get("enabled").map(|v| crate::config::truthy(Some(v))).unwrap_or(true),
            sessions: spec["sessions"].as_array().map(|a| a.iter().map(pyfmt::str).collect()).unwrap_or_default(),
            dests: spec["to"]
                .as_array()
                .map(|a| a.iter().filter_map(|d| parse_destination(&pyfmt::str(d)).ok()).collect())
                .unwrap_or_default(),
            ttl: spec.get("multicast_ttl").and_then(Value::as_u64).unwrap_or(1) as u32,
            context: spec.get("context").and_then(Value::as_object).cloned().unwrap_or_default(),
            stale_s: spec.get("stale_s").and_then(Value::as_f64).unwrap_or(30.0),
            uid_prefix: spec.get("uid_prefix").filter(|v| !v.is_null()).map(pyfmt::str),
            island_rest: island_rest.trim_end_matches('/').into(),
            c: Mutex::new(Counters::default()),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    pub fn wants(&self, session_id: &str) -> bool {
        self.enabled && (self.sessions.is_empty() || self.sessions.iter().any(|s| s == session_id))
    }

    fn counters(&self) -> std::sync::MutexGuard<'_, Counters> {
        self.c.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn udp(&self, c: &mut Counters) -> std::io::Result<()> {
        if c.sock.is_none() {
            let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            s.set_multicast_ttl_v4(self.ttl)?;
            c.sock = Some(s.into());
        }
        Ok(())
    }

    pub fn send(&self, data: &[u8]) {
        for d in &self.dests {
            match d {
                Destination::Udp { text, addr, .. } => {
                    let mut c = self.counters();
                    let r = self.udp(&mut c).and_then(|_| {
                        let to = crate::session::resolve(addr)?;
                        c.sock.as_ref().unwrap().send_to(data, to).map(|_| ())
                    });
                    match r {
                        Ok(()) => {
                            c.sent += 1;
                            c.last_sent = Some(clock::wall());
                        }
                        Err(e) => {
                            c.errors += 1;
                            c.last_error = format!("{text}: {}", pyfmt::os_error(&e));
                            c.sock = None;
                        }
                    }
                }
                Destination::Zenoh { key, .. } => {
                    if let Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) = self.tx.try_send((key.clone(), data.to_vec()))
                    {
                        self.counters().dropped += 1;
                    }
                }
            }
        }
    }

    fn http_worker(&self, stop: Arc<AtomicBool>) {
        let Some(rx) = self.rx.lock().unwrap_or_else(|e| e.into_inner()).take() else { return };
        while !stop.load(Ordering::SeqCst) {
            let Ok((key, data)) = rx.recv_timeout(Duration::from_millis(500)) else { continue };
            let text = format!("zenoh:{key}");
            let text =
                self.dests.iter().find(|d| matches!(d, Destination::Zenoh { key: k, .. } if *k == key)).map(|d| d.text()).unwrap_or(text);
            if self.island_rest.is_empty() {
                let mut c = self.counters();
                c.errors += 1;
                c.last_error = format!("{text}: island_rest is not set (Zenoh REST address)");
                continue;
            }
            let ctype = if self.format == "cot-xml" { "application/xml" } else { "application/octet-stream" };
            let r = crate::http::request(
                "PUT",
                &format!("{}/{key}", self.island_rest),
                &[("Content-Type", ctype)],
                Some(&data),
                Duration::from_secs(3),
            );
            let mut c = self.counters();
            match r {
                Ok(resp) if resp.status < 400 => {
                    c.sent += 1;
                    c.last_sent = Some(clock::wall());
                }
                Ok(resp) => {
                    c.errors += 1;
                    c.last_error = format!("{text}: HTTP Error {}: {}", resp.status, crate::http::reason(resp.status));
                }
                Err(e) => {
                    c.errors += 1;
                    c.last_error = format!("{text}: <urlopen error {}>", e.0);
                }
            }
        }
    }

    pub fn status(&self) -> Value {
        let c = self.counters();
        json!({"name": self.name, "format": self.format, "enabled": self.enabled,
               "to": self.dests.iter().map(|d| d.text()).collect::<Vec<_>>(),
               "sessions": if self.sessions.is_empty() { json!("all") } else { json!(self.sessions) },
               "sent": c.sent, "errors": c.errors, "dropped": c.dropped,
               "last_error": c.last_error,
               "last_sent_age_s": c.last_sent.map(|t| json!(pyfmt::round(clock::wall() - t, 1))).unwrap_or(Value::Null),
               "context": self.context})
    }
}

#[derive(Default)]
struct LayerCounters {
    tracks_in: u64,
    encode_errors: u64,
    last_encode_error: String,
}

/// Every configured output. `publish` is called with each session's normalized tracks.
pub struct OutputLayer {
    pub outputs: Vec<Arc<Output>>,
    pub error: String,
    pub encoder: Option<Encoder>,
    c: Mutex<LayerCounters>,
    stop_flag: Arc<AtomicBool>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl OutputLayer {
    pub fn new(specs: &Map<String, Value>, island_rest: &str, transformers_path: &str) -> OutputLayer {
        Self::new_in(specs, island_rest, transformers_path, &default_search())
    }

    /// As `new`, looking for goat-transformers in `search` after the configured path.
    pub fn new_in(specs: &Map<String, Value>, island_rest: &str, transformers_path: &str, search: &[String]) -> OutputLayer {
        let outputs: Vec<Arc<Output>> = specs.iter().map(|(n, s)| Arc::new(Output::new(n, s, island_rest))).collect();
        let active: Vec<String> = outputs.iter().filter(|o| o.enabled).map(|o| o.format.clone()).collect();
        let (mut encoder, mut error) = (None, String::new());
        if !active.is_empty() {
            let tp = (!transformers_path.is_empty()).then_some(transformers_path);
            match find_transformers_in(tp, search).and_then(|root| Encoder::new(&root, &active)) {
                Ok(e) => encoder = Some(e),
                Err(e) => {
                    crate::log::warning("scapegoat.outputs", &format!("outputs are off: {e}"));
                    error = e;
                }
            }
        }
        OutputLayer {
            outputs,
            error,
            encoder,
            c: Mutex::new(LayerCounters::default()),
            stop_flag: Arc::new(AtomicBool::new(false)),
            threads: Mutex::new(vec![]),
        }
    }

    pub fn start(&self) {
        for o in &self.outputs {
            if o.enabled && o.dests.iter().any(|d| d.is_zenoh()) {
                let (o2, stop) = (o.clone(), self.stop_flag.clone());
                let t = std::thread::Builder::new()
                    .name(format!("scapegoat-output-{}", o.name))
                    .spawn(move || o2.http_worker(stop))
                    .expect("output thread");
                self.threads.lock().unwrap_or_else(|e| e.into_inner()).push(t);
            }
        }
    }

    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        for t in self.threads.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            let _ = t.join();
        }
    }

    /// (output name, enabled, sessions it takes) for the one-track-path warning.
    pub fn wants(&self) -> Vec<(String, bool, Vec<String>)> {
        self.outputs.iter().map(|o| (o.name.clone(), o.enabled, o.sessions.clone())).collect()
    }

    pub fn publish(&self, session_id: &str, tracks: Vec<Track>) -> Result<(), String> {
        let Some(enc) = &self.encoder else { return Ok(()) };
        for t in tracks {
            self.c.lock().unwrap_or_else(|e| e.into_inner()).tracks_in += 1;
            let canon = match canonical_track(&t) {
                Ok(c) => c,
                Err(e) => {
                    let mut c = self.c.lock().unwrap_or_else(|e| e.into_inner());
                    c.encode_errors += 1;
                    c.last_encode_error = format!("track not usable: {e}");
                    continue;
                }
            };
            for o in &self.outputs {
                if !o.wants(session_id) {
                    continue;
                }
                let mut track = canon.clone();
                let mut ctx = o.context.clone();
                if o.format != "asterix-cat062" {
                    let prefix = o.uid_prefix.clone().unwrap_or_else(|| format!("{}-", canon["sourceId"].as_str().unwrap_or("")));
                    track["trackId"] = json!(format!("{prefix}{}", canon["trackId"].as_str().unwrap_or("")));
                }
                if o.format == "cot-xml" {
                    ctx.insert("stale_ms".into(), json!(((num(&t, "time").unwrap_or(0.0) + o.stale_s) * 1000.0) as i64));
                }
                match enc.encode(&o.format, &track, &ctx) {
                    Ok(data) => o.send(&data),
                    Err(e) => {
                        let msg = format!("encode {}: {e}", o.format);
                        let mut c = self.c.lock().unwrap_or_else(|e| e.into_inner());
                        c.encode_errors += 1;
                        c.last_encode_error = msg.clone();
                        let mut oc = o.counters();
                        oc.errors += 1;
                        oc.last_error = msg;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn status(&self) -> Value {
        let c = self.c.lock().unwrap_or_else(|e| e.into_inner());
        json!({"error": self.error,
               "transformers": self.encoder.as_ref().map(|e| json!(e.root)).unwrap_or(Value::Null),
               "tracks_in": c.tracks_in, "encode_errors": c.encode_errors,
               "last_encode_error": c.last_encode_error,
               "outputs": self.outputs.iter().map(|o| o.status()).collect::<Vec<_>>()})
    }
}
