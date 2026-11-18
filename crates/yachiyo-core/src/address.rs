// SPDX-License-Identifier: AGPL-3.0-only

//! Target address representation supporting IPv4, bracketed IPv6, and domain names.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use thiserror::Error;

/// Error encountered while parsing a target address or host.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum AddressParseError {
    #[error("target address string is empty")]
    EmptyInput,

    #[error("host portion is empty")]
    EmptyHost,

    #[error("missing port in target address: {0}")]
    MissingPort(String),

    #[error("invalid port in target address: {0}")]
    InvalidPort(String),

    #[error("missing closing bracket ']' in IPv6 address: {0}")]
    MissingClosingBracket(String),

    #[error("unbracketed IPv6 address with port (must use [::1]:port): {0}")]
    UnbracketedIpv6(String),

    #[error("invalid IPv6 address literal: {0}")]
    InvalidIpv6(String),

    #[error("invalid domain name: {0}")]
    InvalidDomain(String),
}

/// Destination host representation: either an IP address or a domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

impl TargetHost {
    /// Parse a host string (either IP literal, bracketed IPv6, or domain name).
    pub fn parse(s: &str) -> Result<Self, AddressParseError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(AddressParseError::EmptyHost);
        }

        // Bracketed IPv6 literal: [::1]
        if trimmed.starts_with('[') {
            if !trimmed.ends_with(']') || trimmed.len() < 2 {
                return Err(AddressParseError::MissingClosingBracket(
                    trimmed.to_string(),
                ));
            }
            let inner = &trimmed[1..trimmed.len() - 1];
            let v6: Ipv6Addr = inner
                .parse()
                .map_err(|_| AddressParseError::InvalidIpv6(inner.to_string()))?;
            return Ok(TargetHost::Ip(IpAddr::V6(v6)));
        }

        // Plain IP literal (IPv4 or unbracketed IPv6)
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return Ok(TargetHost::Ip(ip));
        }

        // Reject colons (colons in unbracketed host indicate malformed IPv6)
        if trimmed.contains(':') {
            return Err(AddressParseError::UnbracketedIpv6(trimmed.to_string()));
        }

        // Domain name length check (RFC 1035: max 253 octets)
        if trimmed.len() > 253 {
            return Err(AddressParseError::InvalidDomain(
                "domain name exceeds 253 characters".to_string(),
            ));
        }

        // Validate characters: RFC 1123 allowed chars: letters, digits, hyphen, dot, underscore
        for (i, label) in trimmed.split('.').enumerate() {
            if label.is_empty() {
                // Allow trailing dot for FQDN (e.g. "example.com.")
                if i > 0 && trimmed.ends_with('.') && i == trimmed.split('.').count() - 1 {
                    continue;
                }
                return Err(AddressParseError::InvalidDomain(
                    "domain label cannot be empty".to_string(),
                ));
            }
            if label.len() > 63 {
                return Err(AddressParseError::InvalidDomain(
                    "domain label exceeds 63 characters".to_string(),
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(AddressParseError::InvalidDomain(
                    "domain label cannot start or end with a hyphen".to_string(),
                ));
            }
            for c in label.chars() {
                if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                    return Err(AddressParseError::InvalidDomain(format!(
                        "invalid character '{c}' in domain name"
                    )));
                }
            }
        }

        Ok(TargetHost::Domain(trimmed.to_string()))
    }

    /// Check if this host is a loopback destination.
    pub fn is_loopback(&self) -> bool {
        match self {
            TargetHost::Ip(ip) => ip.is_loopback(),
            TargetHost::Domain(domain) => {
                domain.eq_ignore_ascii_case("localhost")
                    || domain.to_ascii_lowercase().ends_with(".localhost")
            }
        }
    }
}

impl fmt::Display for TargetHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetHost::Ip(ip) => write!(f, "{ip}"),
            TargetHost::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

impl From<IpAddr> for TargetHost {
    fn from(ip: IpAddr) -> Self {
        TargetHost::Ip(ip)
    }
}

impl From<Ipv4Addr> for TargetHost {
    fn from(ip: Ipv4Addr) -> Self {
        TargetHost::Ip(IpAddr::V4(ip))
    }
}

impl From<Ipv6Addr> for TargetHost {
    fn from(ip: Ipv6Addr) -> Self {
        TargetHost::Ip(IpAddr::V6(ip))
    }
}

/// Fully qualified target address consisting of host and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetAddr {
    pub host: TargetHost,
    pub port: u16,
}

impl TargetAddr {
    /// Construct a new `TargetAddr` from a `TargetHost` and port.
    pub const fn new(host: TargetHost, port: u16) -> Self {
        Self { host, port }
    }

    /// Construct a `TargetAddr` from an IP address and port.
    pub fn from_ip(ip: impl Into<IpAddr>, port: u16) -> Self {
        Self {
            host: TargetHost::Ip(ip.into()),
            port,
        }
    }

    /// Construct a `TargetAddr` from a domain string and port.
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Result<Self, AddressParseError> {
        let domain_str = domain.into();
        let host = TargetHost::parse(&domain_str)?;
        Ok(Self { host, port })
    }

    /// Get a reference to the host.
    pub const fn host(&self) -> &TargetHost {
        &self.host
    }

    /// Get the destination port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Convert to `std::net::SocketAddr` if host is an IP address.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match &self.host {
            TargetHost::Ip(ip) => Some(SocketAddr::new(*ip, self.port)),
            TargetHost::Domain(_) => None,
        }
    }

    /// Check if target is a loopback address.
    pub fn is_loopback(&self) -> bool {
        self.host.is_loopback()
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            TargetHost::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
            TargetHost::Ip(IpAddr::V4(v4)) => write!(f, "{v4}:{}", self.port),
            TargetHost::Domain(domain) => write!(f, "{domain}:{}", self.port),
        }
    }
}

impl FromStr for TargetAddr {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(AddressParseError::EmptyInput);
        }

        // Case 1: Bracketed IPv6, e.g. "[::1]:8080"
        if trimmed.starts_with('[') {
            let close = trimmed
                .find(']')
                .ok_or_else(|| AddressParseError::MissingClosingBracket(trimmed.to_string()))?;
            let inner = &trimmed[1..close];
            let rest = &trimmed[close + 1..];
            if !rest.starts_with(':') {
                return Err(AddressParseError::MissingPort(trimmed.to_string()));
            }
            let port_str = &rest[1..];
            let port: u16 = port_str
                .parse()
                .map_err(|_| AddressParseError::InvalidPort(port_str.to_string()))?;
            let v6: Ipv6Addr = inner
                .parse()
                .map_err(|_| AddressParseError::InvalidIpv6(inner.to_string()))?;
            return Ok(Self {
                host: TargetHost::Ip(IpAddr::V6(v6)),
                port,
            });
        }

        // Case 2: host:port where host is IPv4 or domain name
        let colon_idx = trimmed
            .rfind(':')
            .ok_or_else(|| AddressParseError::MissingPort(trimmed.to_string()))?;
        let host_part = &trimmed[..colon_idx];
        let port_part = &trimmed[colon_idx + 1..];

        if host_part.is_empty() {
            return Err(AddressParseError::EmptyHost);
        }

        // Unbracketed IPv6 with multiple colons, e.g. "::1:8080"
        if host_part.contains(':') {
            return Err(AddressParseError::UnbracketedIpv6(trimmed.to_string()));
        }

        let port: u16 = port_part
            .parse()
            .map_err(|_| AddressParseError::InvalidPort(port_part.to_string()))?;
        let host = TargetHost::parse(host_part)?;

        Ok(Self { host, port })
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        Self {
            host: TargetHost::Ip(addr.ip()),
            port: addr.port(),
        }
    }
}

impl From<SocketAddrV4> for TargetAddr {
    fn from(addr: SocketAddrV4) -> Self {
        Self {
            host: TargetHost::Ip(IpAddr::V4(*addr.ip())),
            port: addr.port(),
        }
    }
}

impl From<SocketAddrV6> for TargetAddr {
    fn from(addr: SocketAddrV6) -> Self {
        Self {
            host: TargetHost::Ip(IpAddr::V6(*addr.ip())),
            port: addr.port(),
        }
    }
}

impl From<(IpAddr, u16)> for TargetAddr {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        Self {
            host: TargetHost::Ip(ip),
            port,
        }
    }
}

impl TryFrom<(&str, u16)> for TargetAddr {
    type Error = AddressParseError;

    fn try_from((host, port): (&str, u16)) -> Result<Self, Self::Error> {
        let target_host = TargetHost::parse(host)?;
        Ok(Self {
            host: target_host,
            port,
        })
    }
}

impl TryFrom<(String, u16)> for TargetAddr {
    type Error = AddressParseError;

    fn try_from((host, port): (String, u16)) -> Result<Self, Self::Error> {
        Self::try_from((host.as_str(), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_host_display_and_parse() {
        // IPv4
        let host_v4 = TargetHost::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(host_v4.to_string(), "127.0.0.1");
        assert!(host_v4.is_loopback());

        // IPv6
        let host_v6 = TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(host_v6.to_string(), "::1");
        assert!(host_v6.is_loopback());

        // Domain
        let host_domain = TargetHost::Domain("example.com".into());
        assert_eq!(host_domain.to_string(), "example.com");
        assert!(!host_domain.is_loopback());

        let host_localhost = TargetHost::Domain("localhost".into());
        assert!(host_localhost.is_loopback());

        let host_subdomain_localhost = TargetHost::Domain("sub.localhost".into());
        assert!(host_subdomain_localhost.is_loopback());

        // Parse IPv4
        assert_eq!(
            TargetHost::parse("192.168.1.1").unwrap(),
            TargetHost::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        // Parse bracketed IPv6
        assert_eq!(
            TargetHost::parse("[::1]").unwrap(),
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );

        // Parse unbracketed IPv6
        assert_eq!(
            TargetHost::parse("::1").unwrap(),
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );

        // Parse domain
        assert_eq!(
            TargetHost::parse("rust-lang.org").unwrap(),
            TargetHost::Domain("rust-lang.org".into())
        );

        // Invalid hosts
        assert!(matches!(
            TargetHost::parse(""),
            Err(AddressParseError::EmptyHost)
        ));
        assert!(matches!(
            TargetHost::parse("[::1"),
            Err(AddressParseError::MissingClosingBracket(_))
        ));
        assert!(matches!(
            TargetHost::parse("invalid..domain"),
            Err(AddressParseError::InvalidDomain(_))
        ));
        assert!(matches!(
            TargetHost::parse("-invalid.domain"),
            Err(AddressParseError::InvalidDomain(_))
        ));
        assert!(matches!(
            TargetHost::parse("invalid-.domain"),
            Err(AddressParseError::InvalidDomain(_))
        ));
        assert!(matches!(
            TargetHost::parse("invalid:colon:host"),
            Err(AddressParseError::UnbracketedIpv6(_))
        ));
    }

    #[test]
    fn test_target_addr_display_formatting() {
        let v4_addr = TargetAddr::from_ip(Ipv4Addr::new(192, 168, 1, 1), 8080);
        assert_eq!(v4_addr.to_string(), "192.168.1.1:8080");

        let v6_addr = TargetAddr::from_ip(Ipv6Addr::LOCALHOST, 9050);
        assert_eq!(v6_addr.to_string(), "[::1]:9050");

        let domain_addr = TargetAddr::new(TargetHost::Domain("api.openai.com".into()), 443);
        assert_eq!(domain_addr.to_string(), "api.openai.com:443");
    }

    #[test]
    fn test_target_addr_from_str() {
        // IPv4:port
        let addr1: TargetAddr = "127.0.0.1:18484".parse().unwrap();
        assert_eq!(addr1.port(), 18484);
        assert_eq!(
            addr1.host(),
            &TargetHost::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert!(addr1.is_loopback());

        // [IPv6]:port
        let addr2: TargetAddr = "[::1]:8080".parse().unwrap();
        assert_eq!(addr2.port(), 8080);
        assert_eq!(
            addr2.host(),
            &TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(addr2.is_loopback());

        // Domain:port
        let addr3: TargetAddr = "example.com:80".parse().unwrap();
        assert_eq!(addr3.port(), 80);
        assert_eq!(addr3.host(), &TargetHost::Domain("example.com".into()));
        assert!(!addr3.is_loopback());

        // Missing port
        assert!(matches!(
            TargetAddr::from_str("127.0.0.1"),
            Err(AddressParseError::MissingPort(_))
        ));
        assert!(matches!(
            TargetAddr::from_str("[::1]"),
            Err(AddressParseError::MissingPort(_))
        ));
        assert!(matches!(
            TargetAddr::from_str("example.com"),
            Err(AddressParseError::MissingPort(_))
        ));

        // Invalid port
        assert!(matches!(
            TargetAddr::from_str("127.0.0.1:70000"),
            Err(AddressParseError::InvalidPort(_))
        ));
        assert!(matches!(
            TargetAddr::from_str("127.0.0.1:abc"),
            Err(AddressParseError::InvalidPort(_))
        ));

        // Unbracketed IPv6 with port
        assert!(matches!(
            TargetAddr::from_str("::1:8080"),
            Err(AddressParseError::UnbracketedIpv6(_))
        ));

        // Empty
        assert!(matches!(
            TargetAddr::from_str(""),
            Err(AddressParseError::EmptyInput)
        ));

        // Empty host with port
        assert!(matches!(
            TargetAddr::from_str(":8080"),
            Err(AddressParseError::EmptyHost)
        ));
    }

    #[test]
    fn test_target_addr_conversions() {
        let sock: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let target = TargetAddr::from(sock);
        assert_eq!(target.to_string(), "127.0.0.1:8080");
        assert_eq!(target.to_socket_addr(), Some(sock));

        let v4_sock: SocketAddrV4 = "127.0.0.1:8080".parse().unwrap();
        let target_v4 = TargetAddr::from(v4_sock);
        assert_eq!(target_v4.to_string(), "127.0.0.1:8080");

        let v6_sock: SocketAddrV6 = "[::1]:8080".parse().unwrap();
        let target_v6 = TargetAddr::from(v6_sock);
        assert_eq!(target_v6.to_string(), "[::1]:8080");

        let from_tuple = TargetAddr::try_from(("localhost", 18484)).unwrap();
        assert_eq!(from_tuple.to_string(), "localhost:18484");
        assert_eq!(from_tuple.to_socket_addr(), None);
        assert!(from_tuple.is_loopback());

        let from_string_tuple = TargetAddr::try_from(("example.com".to_string(), 443)).unwrap();
        assert_eq!(from_string_tuple.to_string(), "example.com:443");

        let from_domain = TargetAddr::from_domain("example.com", 80).unwrap();
        assert_eq!(from_domain.to_string(), "example.com:80");

        let from_ip_tuple = TargetAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
        assert_eq!(from_ip_tuple.to_string(), "127.0.0.1:8080");
    }
}
