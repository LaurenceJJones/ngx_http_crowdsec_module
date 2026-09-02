//! Trusted reverse-proxy client IP resolution (X-Forwarded-For style).
//!
//! If the TCP peer is listed in `crowdsec_trusted_proxies`, the client address is
//! derived from a configurable header (default `X-Forwarded-For`) using the same
//! right-to-left stripping idea as nginx's `real_ip_recursive on`: walk from the
//! right end of the list, skipping addresses that fall inside trusted CIDRs, and
//! use the first non-trusted address. If the header is missing or unparsable, the
//! socket address is used.

use ngx::http::Request;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One trusted CIDR or host prefix parsed at config time.
#[derive(Debug, Clone, Copy)]
pub enum TrustedCidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl TrustedCidr {
    pub fn parse(s: &str) -> Result<Self, ()> {
        let s = s.trim();
        if s.is_empty() {
            return Err(());
        }
        if let Some((ip_s, plen_s)) = s.split_once('/') {
            let ip: IpAddr = ip_s.trim().parse().map_err(|_| ())?;
            let plen: u32 = plen_s.trim().parse().map_err(|_| ())?;
            match ip {
                IpAddr::V4(v4) => {
                    if plen > 32 {
                        return Err(());
                    }
                    let mask = ipv4_mask(plen);
                    let n = u32::from(v4);
                    Ok(TrustedCidr::V4 {
                        network: n & mask,
                        mask,
                    })
                }
                IpAddr::V6(v6) => {
                    if plen > 128 {
                        return Err(());
                    }
                    let mask = ipv6_mask(plen);
                    let n = u128::from_be_bytes(v6.octets());
                    Ok(TrustedCidr::V6 {
                        network: n & mask,
                        mask,
                    })
                }
            }
        } else {
            let ip: IpAddr = s.parse().map_err(|_| ())?;
            match ip {
                IpAddr::V4(v4) => Ok(TrustedCidr::V4 {
                    network: u32::from(v4),
                    mask: !0u32,
                }),
                IpAddr::V6(v6) => Ok(TrustedCidr::V6 {
                    network: u128::from_be_bytes(v6.octets()),
                    mask: !0u128,
                }),
            }
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (TrustedCidr::V4 { network, mask }, IpAddr::V4(v4)) => {
                (u32::from(*v4) & *mask) == (*network & *mask)
            }
            (TrustedCidr::V6 { network, mask }, IpAddr::V6(v6)) => {
                (u128::from_be_bytes(v6.octets()) & *mask) == (*network & *mask)
            }
            (TrustedCidr::V4 { .. }, IpAddr::V6(_)) | (TrustedCidr::V6 { .. }, IpAddr::V4(_)) => {
                false
            }
        }
    }
}

/// True if `ip` matches any entry in `cidrs` (empty list never matches).
#[inline]
pub fn ip_in_cidr_list(ip: &IpAddr, cidrs: &[TrustedCidr]) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

fn ipv4_mask(prefix_len: u32) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn ipv6_mask(prefix_len: u32) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

fn peer_in_trusted_list(ip: &IpAddr, trusted: &[TrustedCidr]) -> bool {
    trusted.iter().any(|t| t.contains(ip))
}

/// Parse one comma-separated XFF token into an IP (best effort).
fn parse_forwarded_token(tok: &str) -> Option<IpAddr> {
    let t = tok.trim();
    if t.is_empty() {
        return None;
    }
    // Bracketed IPv6, optionally with port: [::1]:443
    if t.starts_with('[') {
        let end = t.find(']')?;
        let inner = t[1..end].split('%').next()?;
        return inner.parse().ok();
    }
    // Zone id: fe80::1%eth0
    let no_zone = t.split('%').next()?;
    if no_zone.contains(':') {
        return no_zone.parse().ok();
    }
    // IPv4 or IPv4:port
    if let Ok(ip) = no_zone.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(colon) = no_zone.rfind(':') {
        no_zone[..colon].parse().ok()
    } else {
        None
    }
}

/// Split `X-Forwarded-For` value into a left-to-right chain of addresses.
pub fn parse_forwarded_chain(value: &str) -> Vec<IpAddr> {
    value.split(',').filter_map(parse_forwarded_token).collect()
}

pub fn header_value_ci<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    for (k, v) in request.headers_in_iterator() {
        let Ok(key) = k.to_str() else {
            continue;
        };
        if key.eq_ignore_ascii_case(name) {
            return v.to_str().ok();
        }
    }
    None
}

/// Resolve the effective client IP given socket peer, trusted CIDR list, and optional header.
pub fn resolve_client_ip(
    socket_ip: IpAddr,
    trusted: &[TrustedCidr],
    header_value: Option<&str>,
) -> IpAddr {
    if trusted.is_empty() || !peer_in_trusted_list(&socket_ip, trusted) {
        return socket_ip;
    }
    let Some(raw) = header_value else {
        return socket_ip;
    };
    let chain = parse_forwarded_chain(raw);
    if chain.is_empty() {
        return socket_ip;
    }
    // Walk from right to left; skip trusted proxies; first non-trusted is the client.
    let mut i = chain.len();
    while i > 0 {
        let ip = chain[i - 1];
        if peer_in_trusted_list(&ip, trusted) {
            i -= 1;
        } else {
            return ip;
        }
    }
    // Entire chain trusted (unusual); use leftmost as best guess.
    chain[0]
}

/// Read client IP from the request connection, then apply trusted-proxy / header rules.
pub fn get_effective_client_ip(
    request: &Request,
    trusted: &[TrustedCidr],
    real_ip_header: Option<&str>,
) -> Option<IpAddr> {
    let socket_ip = socket_peer_ip(request)?;
    let hname = real_ip_header.unwrap_or("X-Forwarded-For");
    let hval = header_value_ci(request, hname);
    Some(resolve_client_ip(socket_ip, trusted, hval))
}

fn socket_peer_ip(request: &Request) -> Option<IpAddr> {
    let connection = request.connection();
    if connection.is_null() {
        return None;
    }
    let sockaddr = unsafe { (*connection).sockaddr };
    if sockaddr.is_null() {
        return None;
    }
    let family = unsafe { (*sockaddr).sa_family };

    #[cfg(target_family = "unix")]
    {
        // AF_INET = 2, AF_INET6 = 10 on Linux
        if family == 2 {
            let addr_in = sockaddr as *const libc::sockaddr_in;
            let ip_bytes = unsafe { (*addr_in).sin_addr.s_addr.to_ne_bytes() };
            return Some(IpAddr::V4(Ipv4Addr::from(ip_bytes)));
        } else if family == 10 {
            let addr_in6 = sockaddr as *const libc::sockaddr_in6;
            let ip_bytes = unsafe { (*addr_in6).sin6_addr.s6_addr };
            return Some(IpAddr::V6(Ipv6Addr::from(ip_bytes)));
        }
    }

    #[cfg(not(target_family = "unix"))]
    {
        let _ = family;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_cidr_host_v4() {
        let t = TrustedCidr::parse("10.0.0.1").unwrap();
        assert!(t.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!t.contains(&"10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn trusted_cidr_slash24() {
        let t = TrustedCidr::parse("10.0.0.0/24").unwrap();
        assert!(t.contains(&"10.0.0.1".parse().unwrap()));
        assert!(!t.contains(&"10.0.1.0".parse().unwrap()));
    }

    #[test]
    fn resolve_strip_right_trusted() {
        let trusted = [
            TrustedCidr::parse("10.0.0.0/8").unwrap(),
            TrustedCidr::parse("203.0.113.0/24").unwrap(),
        ];
        let socket: IpAddr = "10.0.0.1".parse().unwrap();
        let xff = "198.51.100.2, 203.0.113.50, 10.0.0.99";
        let ip = resolve_client_ip(socket, &trusted, Some(xff));
        assert_eq!(ip, "198.51.100.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_untrusted_peer_ignores_header() {
        let trusted = [TrustedCidr::parse("10.0.0.0/8").unwrap()];
        let socket: IpAddr = "198.51.100.1".parse().unwrap();
        let xff = "6.6.6.6, 7.7.7.7";
        let ip = resolve_client_ip(socket, &trusted, Some(xff));
        assert_eq!(ip, socket);
    }

    #[test]
    fn parse_chain_ipv6() {
        let s = "2001:db8::1, 10.0.0.1";
        let c = parse_forwarded_chain(s);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn ip_in_cidr_list_any_match() {
        let list = [
            TrustedCidr::parse("127.0.0.0/8").unwrap(),
            TrustedCidr::parse("192.168.1.1").unwrap(),
        ];
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ip_in_cidr_list(&ip, &list));
        let other: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!ip_in_cidr_list(&other, &list));
        assert!(!ip_in_cidr_list(&ip, &[]));
    }
}
