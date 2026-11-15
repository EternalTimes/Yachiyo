// SPDX-License-Identifier: AGPL-3.0-only

//! Sequential rule evaluation, domain matching, and IPv4/IPv6 CIDR matching.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use tokio::net::lookup_host;
use tracing::debug;

use crate::address::{TargetAddr, TargetHost};

/// Routing action selected by a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Direct,
    Reject,
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "DIRECT"),
            Self::Reject => write!(f, "REJECT"),
        }
    }
}

impl FromStr for Policy {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "DIRECT" => Ok(Self::Direct),
            "REJECT" => Ok(Self::Reject),
            other => Err(RuleError::UnknownPolicy(other.to_string())),
        }
    }
}

/// An IPv4 or IPv6 CIDR network range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl IpCidr {
    /// Parses a CIDR string like `192.0.2.0/24` or `2001:db8::/32`.
    pub fn parse(s: &str) -> Result<Self, RuleError> {
        let s = s.trim();
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| RuleError::InvalidCidr(format!("{s}: missing '/prefix'")))?;

        let ip: IpAddr = addr_str
            .parse()
            .map_err(|_| RuleError::InvalidCidr(format!("{s}: invalid IP address")))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| RuleError::InvalidCidr(format!("{s}: invalid prefix length")))?;

        match ip {
            IpAddr::V4(v4) => {
                if prefix > 32 {
                    return Err(RuleError::InvalidCidr(format!(
                        "{s}: IPv4 prefix length {prefix} > 32"
                    )));
                }
                let mask = if prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix)
                };
                Ok(Self::V4 {
                    network: u32::from(v4) & mask,
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                if prefix > 128 {
                    return Err(RuleError::InvalidCidr(format!(
                        "{s}: IPv6 prefix length {prefix} > 128"
                    )));
                }
                let mask = if prefix == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix)
                };
                Ok(Self::V6 {
                    network: u128::from(v6) & mask,
                    prefix,
                })
            }
        }
    }

    /// Returns `true` if `ip` falls within this CIDR range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, prefix }, IpAddr::V4(v4)) => {
                let mask = if *prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - *prefix)
                };
                (u32::from(v4) & mask) == *network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(v6)) => {
                let mask = if *prefix == 0 {
                    0u128
                } else {
                    !0u128 << (128 - *prefix)
                };
                (u128::from(v6) & mask) == *network
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { network, prefix } => write!(f, "{}/{prefix}", Ipv4Addr::from(*network)),
            Self::V6 { network, prefix } => write!(f, "{}/{prefix}", Ipv6Addr::from(*network)),
        }
    }
}

/// Errors encountered while parsing or validating rules.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("empty rule line")]
    EmptyRule,
    #[error("invalid rule syntax: {0}")]
    InvalidSyntax(String),
    #[error("unknown rule type: {0}")]
    UnknownRuleType(String),
    #[error("unknown policy '{0}' (expected DIRECT or REJECT)")]
    UnknownPolicy(String),
    #[error("invalid domain pattern: {0}")]
    InvalidDomain(String),
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("rules list cannot be empty")]
    EmptyRuleSet,
    #[error("MATCH rule may only appear as the final rule (found at index {0})")]
    MatchNotLast(usize),
    #[error("rules list must end with an explicit MATCH,<POLICY> default rule")]
    MissingFinalMatch,
}

/// A single routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// Exact domain match (case-insensitive, trailing dot normalized).
    Domain { pattern: String, policy: Policy },
    /// Domain suffix match on DNS label boundary.
    DomainSuffix { suffix: String, policy: Policy },
    /// IPv4 or IPv6 CIDR match.
    IpCidr {
        cidr: IpCidr,
        no_resolve: bool,
        policy: Policy,
    },
    /// Explicit catch-all default rule (must be last).
    Match { policy: Policy },
}

impl Rule {
    /// Parses a rule expression such as:
    /// - `DOMAIN,example.com,REJECT`
    /// - `DOMAIN-SUFFIX,example.com,DIRECT`
    /// - `IP-CIDR,192.0.2.0/24,REJECT`
    /// - `IP-CIDR,192.0.2.0/24,REJECT,no-resolve`
    /// - `MATCH,DIRECT`
    pub fn parse(line: &str) -> Result<Self, RuleError> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(RuleError::EmptyRule);
        }

        let parts: Vec<&str> = trimmed.split(',').map(|p| p.trim()).collect();
        let kind = parts[0];

        match kind {
            "DOMAIN" => {
                if parts.len() != 3 {
                    return Err(RuleError::InvalidSyntax(format!(
                        "DOMAIN rule requires 3 fields (DOMAIN,<host>,<policy>): {trimmed}"
                    )));
                }
                let pattern = normalize_domain(parts[1])?;
                let policy = Policy::from_str(parts[2])?;
                Ok(Self::Domain { pattern, policy })
            }
            "DOMAIN-SUFFIX" => {
                if parts.len() != 3 {
                    return Err(RuleError::InvalidSyntax(format!(
                        "DOMAIN-SUFFIX rule requires 3 fields (DOMAIN-SUFFIX,<suffix>,<policy>): {trimmed}"
                    )));
                }
                let suffix = normalize_domain(parts[1])?;
                let policy = Policy::from_str(parts[2])?;
                Ok(Self::DomainSuffix { suffix, policy })
            }
            "IP-CIDR" => {
                if parts.len() != 3 && parts.len() != 4 {
                    return Err(RuleError::InvalidSyntax(format!(
                        "IP-CIDR rule requires 3 or 4 fields (IP-CIDR,<cidr>,<policy>[,no-resolve]): {trimmed}"
                    )));
                }
                let cidr = IpCidr::parse(parts[1])?;
                let policy = Policy::from_str(parts[2])?;
                let no_resolve = match parts.get(3).copied() {
                    None => false,
                    Some("no-resolve") => true,
                    Some(other) => {
                        return Err(RuleError::InvalidSyntax(format!(
                            "unknown IP-CIDR option '{other}' (expected 'no-resolve')"
                        )));
                    }
                };
                Ok(Self::IpCidr {
                    cidr,
                    no_resolve,
                    policy,
                })
            }
            "MATCH" => {
                if parts.len() != 2 {
                    return Err(RuleError::InvalidSyntax(format!(
                        "MATCH rule requires 2 fields (MATCH,<policy>): {trimmed}"
                    )));
                }
                let policy = Policy::from_str(parts[1])?;
                Ok(Self::Match { policy })
            }
            other => Err(RuleError::UnknownRuleType(other.to_string())),
        }
    }

    /// Returns the policy of this rule.
    pub fn policy(&self) -> Policy {
        match self {
            Self::Domain { policy, .. }
            | Self::DomainSuffix { policy, .. }
            | Self::IpCidr { policy, .. }
            | Self::Match { policy } => *policy,
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain { pattern, policy } => write!(f, "DOMAIN,{pattern},{policy}"),
            Self::DomainSuffix { suffix, policy } => write!(f, "DOMAIN-SUFFIX,{suffix},{policy}"),
            Self::IpCidr {
                cidr,
                no_resolve,
                policy,
            } => {
                if *no_resolve {
                    write!(f, "IP-CIDR,{cidr},{policy},no-resolve")
                } else {
                    write!(f, "IP-CIDR,{cidr},{policy}")
                }
            }
            Self::Match { policy } => write!(f, "MATCH,{policy}"),
        }
    }
}

/// Result of evaluating a `RuleSet` against a target destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub policy: Policy,
    pub matched_rule: String,
    pub dns_resolved: bool,
}

/// Ordered list of rules ending with an explicit `MATCH` default rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Creates a validated `RuleSet`.
    pub fn new(rules: Vec<Rule>) -> Result<Self, RuleError> {
        if rules.is_empty() {
            return Err(RuleError::EmptyRuleSet);
        }
        let last_idx = rules.len() - 1;
        for (idx, rule) in rules.iter().enumerate() {
            if matches!(rule, Rule::Match { .. }) && idx != last_idx {
                return Err(RuleError::MatchNotLast(idx));
            }
        }
        if !matches!(rules[last_idx], Rule::Match { .. }) {
            return Err(RuleError::MissingFinalMatch);
        }
        Ok(Self { rules })
    }

    /// Returns a default `RuleSet` that sends all traffic to `DIRECT`.
    pub fn default_direct() -> Self {
        Self {
            rules: vec![Rule::Match {
                policy: Policy::Direct,
            }],
        }
    }

    /// Returns the ordered rules slice.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Evaluates rules in declaration order and returns the first match.
    ///
    /// System DNS resolution is only invoked if an `IP-CIDR` rule without `no-resolve`
    /// is reached while evaluating a domain target. Resolved IPs are cached for the
    /// remainder of this evaluation call; failures to resolve simply skip IP matching
    /// and fall through to subsequent rules (ultimately `MATCH`).
    pub async fn evaluate(&self, target: &TargetAddr) -> RuleMatch {
        let mut resolved_ips: Option<Vec<IpAddr>> = None;
        let mut dns_resolved = false;

        for rule in &self.rules {
            match rule {
                Rule::Domain { pattern, policy } => {
                    if let TargetHost::Domain(dom) = &target.host {
                        let norm = normalize_domain_for_match(dom);
                        if norm == *pattern {
                            return RuleMatch {
                                policy: *policy,
                                matched_rule: rule.to_string(),
                                dns_resolved,
                            };
                        }
                    }
                }
                Rule::DomainSuffix { suffix, policy } => {
                    if let TargetHost::Domain(dom) = &target.host {
                        let norm = normalize_domain_for_match(dom);
                        if domain_matches_suffix(&norm, suffix) {
                            return RuleMatch {
                                policy: *policy,
                                matched_rule: rule.to_string(),
                                dns_resolved,
                            };
                        }
                    }
                }
                Rule::IpCidr {
                    cidr,
                    no_resolve,
                    policy,
                } => match &target.host {
                    TargetHost::Ip(ip) => {
                        if cidr.contains(*ip) {
                            return RuleMatch {
                                policy: *policy,
                                matched_rule: rule.to_string(),
                                dns_resolved,
                            };
                        }
                    }
                    TargetHost::Domain(dom) => {
                        if *no_resolve {
                            continue;
                        }
                        let ips = match &resolved_ips {
                            Some(ips) => ips,
                            None => {
                                dns_resolved = true;
                                let looked_up = match lookup_host((dom.as_str(), target.port)).await
                                {
                                    Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
                                    Err(err) => {
                                        debug!(
                                            target = %target,
                                            error = %err,
                                            "system DNS lookup during IP-CIDR rule evaluation failed; skipping IP-CIDR match"
                                        );
                                        Vec::new()
                                    }
                                };
                                resolved_ips = Some(looked_up);
                                resolved_ips.as_ref().expect("just initialized")
                            }
                        };
                        if ips.iter().any(|ip| cidr.contains(*ip)) {
                            return RuleMatch {
                                policy: *policy,
                                matched_rule: rule.to_string(),
                                dns_resolved,
                            };
                        }
                    }
                },
                Rule::Match { policy } => {
                    return RuleMatch {
                        policy: *policy,
                        matched_rule: rule.to_string(),
                        dns_resolved,
                    };
                }
            }
        }

        unreachable!("RuleSet invariant guarantees a trailing MATCH rule")
    }
}

fn normalize_domain(raw: &str) -> Result<String, RuleError> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty()
        || trimmed.len() > 253
        || trimmed.starts_with('.')
        || trimmed.contains("..")
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(RuleError::InvalidDomain(raw.to_string()));
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return Err(RuleError::InvalidDomain(format!(
            "{raw}: expected domain name, got IP literal"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_domain_for_match(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    if domain.len() > suffix.len() {
        let prefix_len = domain.len() - suffix.len();
        return domain.ends_with(suffix) && domain.as_bytes()[prefix_len - 1] == b'.';
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_ip_cidr_v4_and_v6_matching() {
        let v4 = IpCidr::parse("192.0.2.15/24").unwrap();
        assert_eq!(v4.to_string(), "192.0.2.0/24");
        assert!(v4.contains("192.0.2.1".parse().unwrap()));
        assert!(v4.contains("192.0.2.254".parse().unwrap()));
        assert!(!v4.contains("192.0.3.1".parse().unwrap()));
        assert!(!v4.contains("2001:db8::1".parse().unwrap()));

        let v6 = IpCidr::parse("2001:db8:abcd::1/48").unwrap();
        assert_eq!(v6.to_string(), "2001:db8:abcd::/48");
        assert!(v6.contains("2001:db8:abcd:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db8:abce::1".parse().unwrap()));
        assert!(!v6.contains("192.0.2.1".parse().unwrap()));

        assert!(IpCidr::parse("192.0.2.0/33").is_err());
        assert!(IpCidr::parse("2001:db8::/129").is_err());
        assert!(IpCidr::parse("192.0.2.0").is_err());
    }

    #[test]
    fn test_ruleset_validation_enforces_single_trailing_match() {
        assert_eq!(RuleSet::new(vec![]), Err(RuleError::EmptyRuleSet));
        assert_eq!(
            RuleSet::new(vec![Rule::parse("DOMAIN,example.com,REJECT").unwrap()]),
            Err(RuleError::MissingFinalMatch)
        );
        assert_eq!(
            RuleSet::new(vec![
                Rule::parse("MATCH,DIRECT").unwrap(),
                Rule::parse("DOMAIN,example.com,REJECT").unwrap(),
            ]),
            Err(RuleError::MatchNotLast(0))
        );
    }

    #[test]
    fn test_domain_and_suffix_boundary_evaluation() {
        let rules = RuleSet::new(vec![
            Rule::parse("DOMAIN,Exact.Example.COM.,REJECT").unwrap(),
            Rule::parse("DOMAIN-SUFFIX,example.org,REJECT").unwrap(),
            Rule::parse("MATCH,DIRECT").unwrap(),
        ])
        .unwrap();

        run_async(async move {
            let m1 = rules
                .evaluate(&TargetAddr::new(
                    TargetHost::Domain("exact.example.com".into()),
                    443,
                ))
                .await;
            assert_eq!(m1.policy, Policy::Reject);
            assert!(!m1.dns_resolved);

            let m2 = rules
                .evaluate(&TargetAddr::new(
                    TargetHost::Domain("sub.example.org".into()),
                    443,
                ))
                .await;
            assert_eq!(m2.policy, Policy::Reject);

            let m3 = rules
                .evaluate(&TargetAddr::new(
                    TargetHost::Domain("badexample.org".into()),
                    443,
                ))
                .await;
            assert_eq!(m3.policy, Policy::Direct);
        });
    }

    #[test]
    fn test_ip_cidr_no_resolve_skips_dns_for_domain() {
        let rules = RuleSet::new(vec![
            Rule::parse("IP-CIDR,127.0.0.0/8,REJECT,no-resolve").unwrap(),
            Rule::parse("MATCH,DIRECT").unwrap(),
        ])
        .unwrap();

        run_async(async move {
            let m = rules
                .evaluate(&TargetAddr::new(TargetHost::Domain("localhost".into()), 80))
                .await;
            assert_eq!(m.policy, Policy::Direct);
            assert!(!m.dns_resolved);
        });
    }

    #[test]
    fn test_ip_cidr_resolves_localhost_when_no_resolve_is_false() {
        let rules = RuleSet::new(vec![
            Rule::parse("IP-CIDR,127.0.0.0/8,REJECT").unwrap(),
            Rule::parse("IP-CIDR,::1/128,REJECT").unwrap(),
            Rule::parse("MATCH,DIRECT").unwrap(),
        ])
        .unwrap();

        run_async(async move {
            let m = rules
                .evaluate(&TargetAddr::new(TargetHost::Domain("localhost".into()), 80))
                .await;
            assert_eq!(m.policy, Policy::Reject);
            assert!(m.dns_resolved);
        });
    }
}
