// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! C2 output destinations: `udp://IP:PORT` (unicast or multicast) and `zenoh:<key>`.

use crate::pyfmt;
use std::net::IpAddr;

#[derive(Clone, Debug, PartialEq)]
pub enum Destination {
    Udp { text: String, addr: (String, u16), multicast: bool },
    Zenoh { text: String, key: String },
}

impl Destination {
    pub fn text(&self) -> String {
        match self {
            Destination::Udp { text, .. } | Destination::Zenoh { text, .. } => text.clone(),
        }
    }
    pub fn is_zenoh(&self) -> bool {
        matches!(self, Destination::Zenoh { .. })
    }
}

pub fn parse_destination(text: &str) -> Result<Destination, String> {
    let text = text.trim();
    let r = pyfmt::str_repr(text);
    if let Some(rest) = text.strip_prefix("udp://") {
        let (host, port) = rest.rsplit_once(':').unwrap_or(("", rest));
        let ip: Option<IpAddr> = host.trim_matches(|c| c == '[' || c == ']').parse().ok();
        let p = crate::config::py_int(port);
        let (Some(ip), Some(p)) = (ip, p) else {
            return Err(format!("output destination {r}: expected udp://IP:PORT"));
        };
        if !(1..65536).contains(&p) {
            return Err(format!("output destination {r}: port out of range"));
        }
        return Ok(Destination::Udp { text: text.into(), addr: (ip.to_string(), p as u16), multicast: ip.is_multicast() });
    }
    if let Some(rest) = text.strip_prefix("zenoh:") {
        let key = rest.trim_matches('/');
        if key.is_empty() || key.contains(' ') {
            return Err(format!("output destination {r}: expected zenoh:<key expression>"));
        }
        return Ok(Destination::Zenoh { text: text.into(), key: key.into() });
    }
    Err(format!("output destination {r}: use udp://IP:PORT or zenoh:<key>"))
}
