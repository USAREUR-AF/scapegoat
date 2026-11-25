// SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0
//! An address with its prefix (`192.0.2.177/24`), as Python's `ipaddress.ip_interface`.

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl IfAddr {
    /// `a.b.c.d/n`, `v6/n`, or a bare address (full-length prefix).
    pub fn parse(text: &str) -> Option<IfAddr> {
        let (a, p) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let ip: IpAddr = a.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) => {
                if let Ok(n) = p.parse::<u8>() {
                    n
                } else if let (true, Ok(std::net::IpAddr::V4(m))) = (ip.is_ipv4(), p.parse::<IpAddr>()) {
                    let bits = u32::from(m);
                    if bits.leading_ones() + bits.trailing_zeros() != 32 {
                        return None;
                    }
                    bits.leading_ones() as u8
                } else {
                    return None;
                }
            }
        };
        (prefix <= max).then_some(IfAddr { ip, prefix })
    }

    pub fn is_v4(&self) -> bool {
        self.ip.is_ipv4()
    }

    fn bits(ip: &IpAddr) -> (u128, u32) {
        match ip {
            IpAddr::V4(a) => (u32::from(*a) as u128, 32),
            IpAddr::V6(a) => (u128::from(*a), 128),
        }
    }

    /// Is `ip` inside this address's network?
    pub fn contains(&self, ip: &IpAddr) -> bool {
        if ip.is_ipv4() != self.ip.is_ipv4() {
            return false;
        }
        let (a, w) = Self::bits(&self.ip);
        let (b, _) = Self::bits(ip);
        let host = w - self.prefix as u32;
        if host >= 128 {
            return true;
        }
        (a >> host) == (b >> host)
    }

    /// The network as text: `192.0.2.0/24`.
    pub fn network(&self) -> String {
        let (a, w) = Self::bits(&self.ip);
        let host = w - self.prefix as u32;
        let n = if host >= 128 { 0 } else { (a >> host) << host };
        let ip: IpAddr = if w == 32 { IpAddr::V4((n as u32).into()) } else { IpAddr::V6(n.into()) };
        format!("{ip}/{}", self.prefix)
    }

    pub fn is_link_local(&self) -> bool {
        match self.ip {
            IpAddr::V4(a) => a.is_link_local(),
            IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
        }
    }
}

impl std::fmt::Display for IfAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}
