// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! Simulator for the open `toy` protocol: a peer that waits to be spoken to first.
//!
//! ```text
//! scapegoat sim toy --bind 127.0.0.1:47001 --interval 3
//! ```
//!
//! Like the sensors scapegoat is built for, it sends nothing until a keepalive arrives. Then
//! it answers the sender's address and port every --interval seconds with a keepalive (flag
//! "simulator" set), and sends a data message every --data-every seconds. It answers a
//! keepalive that asks for one (ask 1) at once. --silent-after N stops answering after N
//! seconds, to show a lost link.

use crate::toy::{data_bytes, keepalive_bytes, ToyProtocol, ASK_REPLY, SIMULATOR_FLAG};
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct ToySim {
    pub sock: UdpSocket,
    pub port: u16,
    pub interval: f64,
    pub data_every: f64,
    pub silent_after: Option<f64>,
    pub peer: Option<SocketAddr>,
    pub tx: u16,
    pub rx: u16,
    pub sent: u64,
    pub quiet: bool,
    pub stop: Arc<AtomicBool>,
}

impl ToySim {
    pub fn new(bind: &str, interval: f64, data_every: f64, silent_after: Option<f64>) -> std::io::Result<ToySim> {
        let sock = UdpSocket::bind(bind)?;
        sock.set_read_timeout(Some(Duration::from_millis(100)))?;
        let port = sock.local_addr()?.port();
        Ok(ToySim {
            sock,
            port,
            interval,
            data_every,
            silent_after,
            peer: None,
            tx: 0,
            rx: 0,
            sent: 0,
            quiet: false,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    fn next_tx(&mut self) -> u16 {
        self.tx = if 0 < self.tx && self.tx < 65535 { self.tx + 1 } else { 1 };
        self.tx
    }

    fn ka(&mut self, action: u8) -> Vec<u8> {
        let tx = self.next_tx();
        keepalive_bytes(tx, self.rx, action, SIMULATOR_FLAG)
    }

    fn say(&self, text: &str) {
        if !self.quiet {
            println!("toy-sim: {text}");
            let _ = std::io::stdout().flush();
        }
    }

    pub fn run(&mut self, duration: Option<f64>) {
        let start = Instant::now();
        let (mut next_ka, mut next_data) = (0.0f64, 0.0f64);
        let local = self.sock.local_addr().map(|a| a.ip().to_string()).unwrap_or_default();
        self.say(&format!("listening on UDP {local}:{}; silent until spoken to", self.port));
        let mut buf = [0u8; 2048];
        while !self.stop.load(Ordering::Relaxed) {
            let now = start.elapsed().as_secs_f64();
            if duration.is_some_and(|d| now >= d) {
                break;
            }
            let silent = self.silent_after.is_some_and(|s| now >= s);
            if let Ok((n, addr)) = self.sock.recv_from(&mut buf) {
                for part in ToyProtocol::split_bytes(&buf[..n]).parts {
                    let m = ToyProtocol::decode_bytes(&part);
                    if m.is_keepalive && m.ok {
                        if self.peer != Some(addr) {
                            self.say(&format!("first keepalive from {}:{}; answering there", addr.ip(), addr.port()));
                        }
                        self.peer = Some(addr);
                        self.rx = m.peer_tx_counter.unwrap_or(0) as u16;
                        if m.fields.get("ask").and_then(|v| v.as_i64()) == Some(ASK_REPLY as i64) && !silent {
                            let k = self.ka(0);
                            let _ = self.sock.send_to(&k, addr);
                            self.sent += 1;
                        }
                    }
                }
            }
            let now = start.elapsed().as_secs_f64();
            if let (Some(peer), false) = (self.peer, silent) {
                if now >= next_ka {
                    let k = self.ka(0);
                    let _ = self.sock.send_to(&k, peer);
                    self.sent += 1;
                    next_ka = now + self.interval;
                }
                if self.data_every > 0.0 && now >= next_data {
                    if let Ok(d) = data_bytes(format!("tick {}", self.sent).as_bytes()) {
                        let _ = self.sock.send_to(&d, peer);
                    }
                    next_data = now + self.data_every;
                }
            }
        }
    }
}

fn hostport(text: &str) -> String {
    let (host, port) = text.rsplit_once(':').unwrap_or(("", text));
    format!("{}:{port}", if host.is_empty() { "127.0.0.1" } else { host })
}

const USAGE: &str = "usage: scapegoat sim toy [-h] [--bind BIND] [--interval INTERVAL] [--data-every DATA_EVERY]
                         [--silent-after SILENT_AFTER] [--duration DURATION]";

const HELP: &str = "
Like the sensors scapegoat is built for, it sends nothing until a keepalive arrives. Then
it answers the sender's address and port every --interval seconds with a keepalive (flag
\"simulator\" set), and sends a data message every --data-every seconds. It answers a
keepalive that asks for one (ask 1) at once. --silent-after N stops answering after N
seconds, to show a lost link.

options:
  -h, --help            show this help message and exit
  --bind BIND           address:port to listen on
  --interval INTERVAL   seconds between keepalives
  --data-every DATA_EVERY
                        seconds between data messages (0 = none)
  --silent-after SILENT_AFTER
                        stop answering after N seconds
  --duration DURATION   exit after N seconds";

fn usage_error(msg: &str) -> i32 {
    eprintln!("{USAGE}\nscapegoat sim toy: error: {msg}");
    2
}

/// `scapegoat sim toy [options]`.
pub fn main(argv: Vec<String>) -> i32 {
    let (mut bind, mut interval, mut data_every, mut silent_after, mut duration) = ("127.0.0.1:47001".to_string(), 3.0, 5.0, None, None);
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-h" || a == "--help" {
            println!("{USAGE}\n{HELP}");
            return 0;
        }
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let known = ["--bind", "--interval", "--data-every", "--silent-after", "--duration"];
        let matches: Vec<&str> = known.iter().copied().filter(|k| k.starts_with(flag.as_str()) && flag.starts_with("--")).collect();
        let name = match matches.as_slice() {
            [one] => *one,
            [] => return usage_error(&format!("unrecognized arguments: {}", argv[i..].join(" "))),
            _ => return usage_error(&format!("ambiguous option: {flag} could match {}", matches.join(", "))),
        };
        let value = match inline {
            Some(v) => v,
            None => {
                i += 1;
                match argv.get(i) {
                    Some(v) => v.clone(),
                    None => return usage_error(&format!("argument {name}: expected one argument")),
                }
            }
        };
        if name == "--bind" {
            bind = value;
        } else {
            let Ok(f) = value.trim().parse::<f64>() else {
                return usage_error(&format!("argument {name}: invalid float value: {}", crate::pyfmt::str_repr(&value)));
            };
            match name {
                "--interval" => interval = f,
                "--data-every" => data_every = f,
                "--silent-after" => silent_after = Some(f),
                _ => duration = Some(f),
            }
        }
        i += 1;
    }
    let mut sim = match ToySim::new(&hostport(&bind), interval, data_every, silent_after) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("toy-sim: cannot listen on {bind}: {}", crate::pyfmt::os_error(&e));
            return 1;
        }
    };
    crate::signals::on_stop(sim.stop.clone());
    sim.run(duration);
    0
}
