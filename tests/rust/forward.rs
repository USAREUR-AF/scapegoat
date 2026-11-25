// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! tests/test_forward.py: forwarding survives a forward target going away and coming back.

use crate::support::*;
use scapegoat::config::Addr;
use scapegoat::session::{FwdSock, FwdState, Session, FORWARD_ROTATE_S};
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Fixture {
    _sensor: FakeSensor,
    fport: u16,
    s: Session,
    addr: Addr,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.s.stop();
    }
}

fn fixture() -> Fixture {
    let sensor = FakeSensor::start(0.2);
    let fport = free_udp_port();
    let cfg = make_config(sensor.port, free_udp_port(), Opts { forward: vec![format!("127.0.0.1:{fport}")], ..Default::default() });
    let s = Session::new(cfg.sessions[0].clone(), fake());
    s.start();
    assert!(wait_for(|| s.with(|i| i.sock.is_some()), 2.0));
    let addr = ("127.0.0.1".to_string(), sensor.port);
    Fixture { _sensor: sensor, fport, s, addr }
}

fn refused() -> io::Error {
    io::Error::from_raw_os_error(libc::ECONNREFUSED)
}

struct Refusing(Arc<AtomicUsize>);
impl FwdSock for Refusing {
    fn send_to(&self, _: &[u8], _: &Addr) -> io::Result<usize> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(refused())
    }
}

struct AlwaysRefusing;
impl FwdSock for AlwaysRefusing {
    fn send_to(&self, _: &[u8], _: &Addr) -> io::Result<usize> {
        Err(refused())
    }
}

fn sock_ptr(s: &Session) -> Option<u16> {
    s.with(|i| i.fwd_sock.as_ref().and_then(|b| b.local_port()))
}

#[test]
fn test_target_down_then_up_resumes_without_restart() {
    let f = fixture();
    // target down: copies go nowhere
    for _ in 0..20 {
        f.s.handle(b"DTdown", &f.addr);
        std::thread::sleep(Duration::from_millis(10));
    }
    let r = UdpSocket::bind(("127.0.0.1", f.fport)).unwrap();
    r.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    let mut got = false;
    let mut buf = [0u8; 64];
    while !got && Instant::now() < end {
        f.s.handle(b"DTup", &f.addr);
        if let Ok((n, _)) = r.recv_from(&mut buf) {
            got = &buf[..n] == b"DTup";
        }
    }
    assert!(got, "forwards resume once the target listens again");
}

#[test]
fn test_send_error_counts_logs_and_replaces_the_socket() {
    let f = fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    f.s.with(|i| i.fwd_sock = Some(Box::new(Refusing(calls.clone()))));
    let bad = sock_ptr(&f.s);
    let before = f.s.with(|i| i.forwarded);
    f.s.handle(b"DTx", &f.addr);
    assert_eq!(f.s.with(|i| i.forwarded), before + 1, "the retry on a new socket went out");
    assert_eq!(f.s.with(|i| i.forward_errors), 1);
    assert_ne!(sock_ptr(&f.s), bad);
    assert_eq!(f.s.status(0)["forward_socket_replaced"], 1);
    assert!(has_event(&f.s, |e| e["kind"] == "forward"));
    let t = f.s.get_traffic(None, 50);
    let fails: Vec<&serde_json::Value> = t["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["direction"] == "fwd" && !e["problems"].as_array().unwrap().is_empty())
        .collect();
    assert!(!fails.is_empty() && fails[0]["problems"][0].as_str().unwrap().contains("Connection refused"), "{fails:?}");
}

#[test]
fn test_refusing_for_more_than_10_s_is_a_problem() {
    let f = fixture();
    f.s.with(|i| {
        i.fwd_factory = || Box::new(AlwaysRefusing);
        i.fwd_sock = Some(Box::new(AlwaysRefusing));
    });
    let before = f.s.with(|i| i.forwarded);
    f.s.handle(b"DTx", &f.addr);
    assert_eq!(f.s.with(|i| i.forwarded), before, "a refused copy is not counted");
    let t0 = scapegoat::clock::mono();
    f.s.with(|i| {
        for (_, st) in i.fwd_state.iter_mut() {
            // refusals kept arriving for 11 s
            st.refused_since = Some(t0 - 11.0);
            st.last_refused = Some(t0);
        }
        i.check_forwards(t0);
    });
    let st = f.s.status(0);
    let probs: Vec<String> = st["problems"].as_array().unwrap().iter().map(|p| p["problem"].as_str().unwrap().to_string()).collect();
    let want = format!("forward target 127.0.0.1:{}: receiver not receiving", f.fport);
    assert!(probs.iter().any(|p| p.starts_with(&want) && p.contains("billie kid activate")), "{probs:?}");
    assert!(st["forward_targets"][format!("127.0.0.1:{}", f.fport)]["errors"].as_u64().unwrap() >= 2);
}

#[test]
fn test_refusals_stop_streak_clears() {
    let f = fixture();
    let now = scapegoat::clock::mono();
    let target = ("127.0.0.1".to_string(), f.fport);
    f.s.with(|i| {
        i.fwd_state.push((
            target.clone(),
            FwdState {
                refused_since: Some(now - 30.0),
                last_refused: Some(now - 20.0),
                last_ok: Some(now),
                errors: 3,
                last_error: "x".into(),
            },
        ));
        i.check_forwards(scapegoat::clock::mono());
    });
    assert!(f.s.with(|i| i.fwd_state[0].1.refused_since.is_none()));
    assert!(f.s.status(0)["problems"].as_array().unwrap().is_empty());
}

#[test]
fn test_periodic_rotation_gives_a_new_source_port() {
    let f = fixture();
    let old = sock_ptr(&f.s);
    f.s.with(|i| i.check_forwards(scapegoat::clock::mono() + FORWARD_ROTATE_S + 1.0));
    assert_ne!(sock_ptr(&f.s), old);
    assert_eq!(f.s.status(0)["forward_socket_replaced"], 0, "rotation is not an error");
}
