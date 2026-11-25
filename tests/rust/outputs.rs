// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_outputs.py: geodesy, canonical tracks, config, and encoding with
//! goat-transformers (the encoding tests are skipped when no goat-transformers tree is found:
//! GOAT_TRANSFORMERS_PATH or the usual checkout), and tests/test_field_node_outputs.py.

use crate::support::*;
use scapegoat::config;
use scapegoat::outputs::{self as out, OutputLayer};
use scapegoat::protocol::{Decoded, HookResult, Protocol, Track};
use scapegoat::service::Service;
use scapegoat::session::Session;
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn gt_root() -> Option<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let gt = std::env::var("GOAT_TRANSFORMERS_PATH")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or(format!("{home}/src/github.com/USAREUR-AF/goat-transformers"));
    out::find_transformers(Some(&gt)).ok()
}

macro_rules! need_gt {
    () => {
        match gt_root() {
            Some(r) => r,
            None => {
                eprintln!("skipped: goat-transformers not found; set GOAT_TRANSFORMERS_PATH");
                return;
            }
        }
    };
}

fn sample_track(over: Value) -> Track {
    let mut t = json!({"track_id": 1203, "source_id": "sensor-7", "time": 1700000000.25, "lat": 44.4268, "lon": 26.1025,
                       "hae": 150.0, "vel_east": -12.5, "vel_north": 4.25, "vel_up": 0.0, "confirmed": true});
    for (k, v) in over.as_object().unwrap() {
        t[k] = v.clone();
    }
    t.as_object().unwrap().clone()
}

fn udp_listener() -> (UdpSocket, u16) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let p = s.local_addr().unwrap().port();
    (s, p)
}

fn specs(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn close(a: f64, b: f64, places: i32) -> bool {
    ((a - b) * 10f64.powi(places)).round() == 0.0
}

#[test]
fn test_round_trip() {
    for (lat, lon, h) in [(44.4268, 26.1025, 150.0), (-33.9, 151.2, 30.0), (0.0, 0.0, 0.0), (89.9, -179.9, 10000.0)] {
        let (x, y, z) = out::geodetic_to_ecef(lat, lon, h);
        let (la, lo, hh) = out::ecef_to_geodetic(x, y, z);
        assert!(close(la, lat, 9) && close(lo, lon, 9) && close(hh, h, 3), "{la} {lo} {hh}");
    }
}

#[test]
fn test_velocity_enu() {
    let (lat, lon) = (44.4268f64, 26.1025f64);
    let (la, lo) = (lat.to_radians(), lon.to_radians());
    // a pure "north" ECEF velocity of 10 m/s built from the ENU basis
    let n = (-la.sin() * lo.cos(), -la.sin() * lo.sin(), la.cos());
    let (e, nn, u) = out::ecef_velocity_to_enu(10.0 * n.0, 10.0 * n.1, 10.0 * n.2, lat, lon);
    assert!(close(e, 0.0, 9) && close(nn, 10.0, 9) && close(u, 0.0, 9));
}

#[test]
fn test_canonical_track() {
    let c = out::canonical_track(&sample_track(json!({}))).unwrap();
    assert_eq!((c["trackId"].clone(), c["observedAt"].clone()), (json!("1203"), json!("2023-11-14T22:13:20.250Z")));
    assert_eq!(c["velocity"], json!({"eastMps": -12.5, "northMps": 4.25, "upMps": 0.0}));
    let c = out::canonical_track(&sample_track(
        json!({"hae": null, "vel_east": null, "vel_north": null, "vel_up": null, "classification": "uas"}),
    ))
    .unwrap();
    assert!(c["position"].get("altitudeM").is_none());
    assert!(c.get("velocity").is_none());
    assert_eq!(c["classification"], "uas");
}

mod config_tests {
    use super::*;

    #[test]
    fn test_parse() {
        let cfg = config::from_dict(
            &json!({"outputs": {
                "cat062": {"format": "asterix-cat062", "to": ["udp://239.255.62.1:8600"], "sac": 1, "sic": 7},
                "cot": {"format": "cot-xml", "to": ["udp://127.0.0.1:6969"], "enabled": false}}}),
            "",
        )
        .unwrap();
        assert_eq!(cfg.outputs["cat062"]["context"], json!({"cat062.sac": 1, "cat062.sic": 7}));
        assert_eq!(cfg.outputs["cot"]["enabled"], false);
    }

    #[test]
    fn test_refusals() {
        for (bad, msg) in [
            (json!({"x": {"format": "cat048", "to": ["udp://127.0.0.1:1"]}}), "format"),
            (json!({"x": {"format": "asterix-cat062", "to": ["udp://127.0.0.1:1"]}}), "sac"),
            (json!({"x": {"format": "asterix-cat062", "to": ["udp://127.0.0.1:1"], "sac": 1, "sic": 300}}), "sic"),
            (json!({"x": {"format": "cot-xml", "to": ["tcp://127.0.0.1:1"]}}), "udp://"),
            (json!({"x": {"format": "cot-xml", "to": []}}), "destinations"),
            (json!({"x": {"format": "cot-xml", "to": ["zenoh:a/b"]}}), "island_rest"),
            (json!({"x": {"format": "sapient", "to": ["udp://127.0.0.1:1"]}}), "node_id"),
        ] {
            let e = config::from_dict(&json!({"outputs": bad}), "").unwrap_err();
            assert!(e.0.contains(msg), "{msg}: {e}");
        }
    }

    #[test]
    fn test_missing_transformers_turns_outputs_off() {
        // As Python's mock of the environment and TRANSFORMERS_DIRS: nowhere to look but the path.
        let layer = OutputLayer::new_in(
            &specs(json!({"c": {"format": "cot-xml", "to": ["udp://127.0.0.1:9"], "enabled": true, "context": {"how": "m-g"}}})),
            "",
            "/nonexistent",
            &[],
        );
        assert!(layer.encoder.is_none());
        assert!(layer.status()["error"].as_str().unwrap().contains("goat-transformers not found"));
        layer.publish("s", vec![sample_track(json!({}))]).unwrap(); // off: nothing happens, nothing fails
        assert_eq!(layer.status()["outputs"][0]["sent"], 0);
    }
}

/// UTC "YYYY-MM-DDTHH:MM:SS" -> epoch seconds.
fn epoch(s: &str) -> Option<f64> {
    let p = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (p(0, 4)?, p(5, 7)?, p(8, 10)?, p(11, 13)?, p(14, 16)?, p(17, 19)?);
    let (y2, m2) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss) as f64)
}

mod encoding {
    use super::*;

    #[test]
    fn test_conformance_with_goat_transformers_vectors() {
        // A normalized track equal to each to-asterix-cat062 vector input encodes to the
        // vector's bytes.
        let root = need_gt!();
        let enc = out::Encoder::new(&root, &["asterix-cat062".into()]).unwrap();
        let dir = std::path::Path::new(&root).join("packs/canonical-track-v2/vectors");
        let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok().map(|e| e.path())).collect();
        files.sort();
        let mut n = 0;
        for f in files {
            let name = f.file_name().unwrap().to_string_lossy().to_string();
            if !(name.contains("-to-asterix-cat062-") && name.ends_with(".json")) {
                continue;
            }
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
            if !scapegoat::config::truthy(v.get("expect")) || v.get("error").is_some() || !scapegoat::config::truthy(v.get("context")) {
                continue;
            }
            let i: Value = serde_json::from_str(v["input"].as_str().unwrap()).unwrap();
            let obs = i["observedAt"].as_str().unwrap();
            let Some(base) = epoch(obs) else { continue };
            let Ok(frac) = format!("0.{}", obs.get(20..23).unwrap_or("")).parse::<f64>() else { continue };
            let ts = base + frac;
            let (p, vel) = (&i["position"], i.get("velocity").cloned().unwrap_or(json!({})));
            if i.get("headerSimulated") == Some(&json!(true)) && i.get("simulated") != Some(&json!(true)) {
                continue; // a header-only flag the normalized track does not carry
            }
            let t = json!({"track_id": i["trackId"], "source_id": i["sourceId"], "generation": i["trackGeneration"], "time": ts,
                           "lat": p["latitudeDeg"], "lon": p["longitudeDeg"], "hae": p.get("altitudeM"),
                           "vel_east": vel.get("eastMps"), "vel_north": vel.get("northMps"), "vel_up": vel.get("upMps"),
                           "confirmed": i.get("confirmed").cloned().unwrap_or(json!(true)),
                           "coasting": i.get("coasting").cloned().unwrap_or(json!(false)),
                           "final": i.get("finalUpdate").cloned().unwrap_or(json!(false)),
                           "simulated": i.get("simulated") == Some(&json!(true)) || i.get("headerSimulated") == Some(&json!(true))});
            let canon = out::canonical_track(t.as_object().unwrap()).unwrap();
            let got = enc.encode("asterix-cat062", &canon, v["context"].as_object().unwrap()).unwrap();
            assert_eq!(scapegoat::traffic::hex(&got), v["expect"].as_str().unwrap(), "{name}");
            n += 1;
        }
        assert!(n >= 4, "{n} vectors");
    }

    #[test]
    fn test_cat062_to_udp_round_trip() {
        let root = need_gt!();
        let (rx, port) = udp_listener();
        let layer = OutputLayer::new(
            &specs(
                json!({"cat062": {"format": "asterix-cat062", "to": [format!("udp://127.0.0.1:{port}")], "enabled": true, "context": {"cat062.sac": 1, "cat062.sic": 7}}}),
            ),
            "",
            &root,
        );
        layer.publish("sensor", vec![sample_track(json!({}))]).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        assert_eq!(buf[0], 62);
        let f = layer.encoder.as_ref().unwrap().decode("asterix-cat062", &buf[..n]).unwrap();
        assert_eq!((f["cat062.sac"].clone(), f["cat062.sic"].clone(), f["cat062.track_number"].clone()), (json!(1), json!(7), json!(1203)));
        assert!(close(f["lat"].as_f64().unwrap(), 44.4268, 5));
        assert!(close(f["lon"].as_f64().unwrap(), 26.1025, 5));
        assert!(close(f["track.vel_east_ms"].as_f64().unwrap(), -12.5, 7));
        assert_eq!(layer.status()["outputs"][0]["sent"], 1);
    }

    #[test]
    fn test_cot_to_udp_and_disabled_output() {
        let root = need_gt!();
        let (rx, port) = udp_listener();
        let (rx2, port2) = udp_listener();
        let layer = OutputLayer::new(
            &specs(json!({
                "cot": {"format": "cot-xml", "to": [format!("udp://127.0.0.1:{port}")], "enabled": true, "context": {"how": "m-r"}, "stale_s": 30},
                "off": {"format": "cot-xml", "to": [format!("udp://127.0.0.1:{port2}")], "enabled": false, "context": {"how": "m-r"}}})),
            "",
            &root,
        );
        layer.publish("sensor", vec![sample_track(json!({"classification": "uas"}))]).unwrap();
        let mut buf = [0u8; 8192];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        let xml = String::from_utf8_lossy(&buf[..n]).to_string();
        rx2.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        assert!(rx2.recv_from(&mut [0u8; 100]).is_err());
        assert!(xml.contains("uid=\"sensor-7-1203\""), "{xml}");
        assert!(xml.contains("type=\"a-u-A-M-F-Q\""));
        assert!(xml.contains("stale=\"2023-11-14T22:13:50.250Z\""));
        assert!(xml.contains("how=\"m-r\""));
    }

    #[test]
    fn test_zenoh_destination_puts_to_island_rest() {
        let root = need_gt!();
        type Puts = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
        let got: Puts = Arc::new(Mutex::new(vec![]));
        let srv = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        let g2 = got.clone();
        std::thread::spawn(move || {
            for c in srv.incoming() {
                let Ok(mut c) = c else { continue };
                let mut buf = vec![0u8; 65536];
                let mut have = 0;
                loop {
                    let n = c.read(&mut buf[have..]).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    have += n;
                    let text = String::from_utf8_lossy(&buf[..have]).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len: usize = text
                            .lines()
                            .find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                            .unwrap_or(0);
                        if have >= end + 4 + len {
                            let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
                            g2.lock().unwrap().push((path, buf[end + 4..end + 4 + len].to_vec()));
                            let _ = c.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
                            break;
                        }
                    }
                }
            }
        });
        let layer = OutputLayer::new(
            &specs(
                json!({"cat062": {"format": "asterix-cat062", "to": ["zenoh:site/sensor/cat062"], "enabled": true, "context": {"cat062.sac": 1, "cat062.sic": 7}}}),
            ),
            &format!("http://127.0.0.1:{port}"),
            &root,
        );
        layer.start();
        layer.publish("sensor", vec![sample_track(json!({}))]).unwrap();
        assert!(wait_for(|| !got.lock().unwrap().is_empty(), 3.0));
        layer.stop();
        let g = got.lock().unwrap();
        assert_eq!(g[0].0, "/site/sensor/cat062");
        assert_eq!(g[0].1[0], 62);
    }

    struct Tracking(FakeProtocol);

    impl Protocol for Tracking {
        fn name(&self) -> &str {
            "fake"
        }
        fn keepalive(&mut self, link: &mut scapegoat::protocol::LinkState, action: i64) -> HookResult<Vec<u8>> {
            self.0.keepalive(link, action)
        }
        fn decode(&mut self, d: &[u8]) -> Decoded {
            self.0.decode(d)
        }
        fn tracks(&mut self, msg: &Decoded) -> Option<HookResult<Vec<Track>>> {
            Some(Ok(if msg.name == "Data" { vec![sample_track(json!({"track_id": 7}))] } else { vec![] }))
        }
    }

    #[test]
    fn test_session_tracks_hook_feeds_outputs() {
        let root = need_gt!();
        let sensor = FakeSensor::start(0.2);
        let (rx, port) = udp_listener();
        let cfg = make_config(
            sensor.port,
            free_udp_port(),
            Opts {
                extra: json!({"transformers": {"path": root},
                              "outputs": {"cat062": {"format": "asterix-cat062", "to": [format!("udp://127.0.0.1:{port}")], "sac": 1, "sic": 7}}}),
                ..Default::default()
            },
        );
        let s = Session::new(cfg.sessions[0].clone(), Some(Box::new(Tracking(FakeProtocol::default()))));
        let svc = Service::new(cfg, Some(vec![s]), None).unwrap();
        let _run = Running(svc.clone());
        svc.start(false).unwrap();
        assert!(wait_for(|| sensor.peer().is_some(), 3.0));
        sensor.send(b"DTtrack");
        let mut buf = [0u8; 4096];
        let (n, _) = rx.recv_from(&mut buf).unwrap();
        let f = svc.outputs.encoder.as_ref().unwrap().decode("asterix-cat062", &buf[..n]).unwrap();
        assert_eq!(f["cat062.track_number"], 7);
        assert_eq!(svc.health()["outputs"]["outputs"][0]["sent"], 1);
    }
}

// ---- tests/test_field_node_outputs.py: the site file's C2 output settings render into
// scapegoat.toml [outputs.*], which this crate's loader reads.
const SITE: &str = "NODE_NAME=c2-node
NODE_ROLE=\"C2 node\"
SENSOR_IFACE=eth0
LAN_LOCAL_CIDR=192.0.2.10/24
LAN_PEER=192.0.2.81:47000
LAN_PEER_CANDIDATES=\"192.0.2.81:47000\"
ISLAND_REST=http://127.0.0.1:8000
GOAT_TRANSFORMERS_PATH=/opt/goat-transformers
SCAPEGOAT_OUTPUTS=\"cat062 cot\"
OUTPUT_CAT062_FORMAT=asterix-cat062
OUTPUT_CAT062_TO=\"udp://239.255.62.1:8600 zenoh:site/sensor/cat062\"
OUTPUT_CAT062_SAC=38
OUTPUT_CAT062_SIC=202
OUTPUT_COT_FORMAT=cot-xml
OUTPUT_COT_ENABLED=false
OUTPUT_COT_TO=\"udp://239.2.3.1:6969\"
OUTPUT_COT_HOW=m-r
OUTPUT_COT_STALE_S=20
";

fn render(site: &str) -> config::Config {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let field = repo.join("deploy/field-node");
    let d = crate::core::tempdir("fieldnode");
    let site_file = d.join("site.env");
    std::fs::write(&site_file, site).unwrap();
    let o = std::process::Command::new(field.join("components/scapegoat-field-config"))
        .args(["lan", "--no-restart"])
        .env("FIELD_ROOT", &d)
        .env("FIELD_ENV", &site_file)
        .env("FIELD_PACK_DIR", field.join("packs/toy"))
        .env("FIELD_PROGRAM", &repo)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let conf = d.join("etc/scapegoat/scapegoat.toml");
    let cfg = config::load(conf.to_str().unwrap(), None).unwrap();
    let _ = std::fs::remove_dir_all(&d);
    cfg
}

#[test]
fn test_site_outputs_render_and_load() {
    let cfg = render(SITE);
    let o = &cfg.outputs;
    assert_eq!(o["cat062"]["to"], json!(["udp://239.255.62.1:8600", "zenoh:site/sensor/cat062"]));
    assert_eq!(o["cat062"]["context"], json!({"cat062.sac": 38, "cat062.sic": 202}));
    assert_eq!(o["cot"]["enabled"], false);
    assert_eq!((o["cot"]["context"].clone(), o["cot"]["stale_s"].clone()), (json!({"how": "m-r"}), json!(20.0)));
    assert_eq!(cfg.transformers_path, "/opt/goat-transformers");
}

#[test]
fn test_no_outputs_renders_none() {
    let cfg = render(SITE.split("GOAT_TRANSFORMERS_PATH").next().unwrap());
    assert!(cfg.outputs.is_empty());
}
