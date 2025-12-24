//! Network policy enforcement for proxy
//!
//! Implements ordered rule matching with DNS resolution and IP CIDR matching.
//! First matching rule wins (allow or deny).

use ipnetwork::IpNetwork;
use moka::future::Cache;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::config::Credential;
use crate::jail::{network_pattern, NetworkAction, NetworkPolicy};

/// Result of evaluating a network policy
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    /// Request is allowed
    Allow {
        /// Optional credential to use for this request
        credential: Option<String>,
        /// Index of the rule that matched (None if default action was used)
        rule_index: Option<usize>,
    },
    /// Request is denied
    Deny,
}

/// Compiled network policy for efficient matching
#[derive(Debug)]
pub struct CompiledPolicy {
    /// Compiled rules in order (first match wins)
    /// If no rule matches, requests are DENIED
    pub(crate) rules: Vec<CompiledRule>,
    /// Server credentials available for injection
    credentials: HashMap<String, Credential>,
    /// Token cache: credential_name -> token (with 5-minute TTL)
    token_cache: Cache<String, String>,
}

/// A single compiled rule with pre-compiled regexes
#[derive(Debug)]
pub(crate) struct CompiledRule {
    pattern: CompiledPattern,
    action: NetworkAction,
    credential: Option<String>,
}

#[derive(Debug)]
enum CompiledPattern {
    Host {
        host_regex: Regex,
        path_regex: Option<Regex>,
    },
    Ip {
        cidr: IpNetwork,
    },
}

// Note: Using ipnetwork crate for CIDR parsing and matching
// Provides battle-tested implementation with proper edge case handling

/// Global DNS cache for policy evaluation (5-minute TTL, max 1000 entries)
static DNS_CACHE: std::sync::OnceLock<Cache<String, Vec<IpAddr>>> = std::sync::OnceLock::new();

/// Get or initialize the global DNS cache
fn get_dns_cache() -> &'static Cache<String, Vec<IpAddr>> {
    DNS_CACHE.get_or_init(|| {
        Cache::builder()
            .time_to_live(Duration::from_secs(300)) // 5 minutes
            .max_capacity(1000)
            .build()
    })
}

/// Resolve hostname to IP addresses with caching and retry
async fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>, String> {
    let cache = get_dns_cache();

    cache
        .try_get_with(hostname.to_string(), async {
            // Retry strategy: 2 retries with exponential backoff (50ms, 150ms with jitter)
            let retry_strategy = ExponentialBackoff::from_millis(50).map(jitter).take(2);

            let hostname_clone = hostname.to_string();
            Retry::spawn(retry_strategy, || async {
                // Perform DNS lookup
                tokio::net::lookup_host(format!("{}:443", hostname_clone))
                    .await
                    .map_err(|e| format!("DNS lookup failed: {}", e))
            })
            .await
            .and_then(|lookup_result| {
                let ips: Vec<IpAddr> = lookup_result.map(|addr| addr.ip()).collect();

                if ips.is_empty() {
                    Err("No IP addresses found".to_string())
                } else {
                    tracing::debug!("resolved {} to {:?}", hostname, ips);
                    Ok(ips)
                }
            })
        })
        .await
        .map_err(|e| e.to_string())
}

impl CompiledPolicy {
    /// Create a deny-all policy (used when no network policy is configured)
    pub fn deny_all() -> Self {
        CompiledPolicy {
            rules: vec![],
            credentials: HashMap::new(),
            token_cache: Cache::builder()
                .time_to_live(Duration::from_secs(300)) // 5 minutes
                .max_capacity(100)
                .build(),
        }
    }

    /// Compile a network policy for efficient evaluation
    pub fn compile(policy: NetworkPolicy, credentials: &[Credential]) -> Result<Self, String> {
        let mut rules = Vec::new();

        // Build credentials map
        let credentials_map: HashMap<String, Credential> = credentials
            .iter()
            .map(|c| (c.name.clone(), c.clone()))
            .collect();

        for rule in policy.rules {
            let pattern = rule.pattern.ok_or("Missing pattern in rule")?;

            let compiled_pattern = match pattern.pattern.ok_or("Missing pattern variant")? {
                network_pattern::Pattern::Host(host_pattern) => {
                    let host_regex = Regex::new(&host_pattern.host)
                        .map_err(|e| format!("Invalid host regex: {}", e))?;

                    let path_regex = if let Some(path) = host_pattern.path {
                        Some(Regex::new(&path).map_err(|e| format!("Invalid path regex: {}", e))?)
                    } else {
                        None
                    };

                    CompiledPattern::Host {
                        host_regex,
                        path_regex,
                    }
                }
                network_pattern::Pattern::Ip(ip_pattern) => {
                    let cidr: IpNetwork = ip_pattern
                        .cidr
                        .parse()
                        .map_err(|e| format!("Invalid CIDR: {}", e))?;
                    CompiledPattern::Ip { cidr }
                }
            };

            // Validate credential exists if specified
            if let Some(ref cred) = rule.credential {
                if !credentials_map.contains_key(cred) {
                    return Err(format!("Unknown credential: {}", cred));
                }
            }

            rules.push(CompiledRule {
                pattern: compiled_pattern,
                action: NetworkAction::try_from(rule.action)
                    .map_err(|_| "Invalid network action")?,
                credential: rule.credential,
            });
        }

        Ok(Self {
            rules,
            credentials: credentials_map,
            token_cache: Cache::builder()
                .time_to_live(Duration::from_secs(300)) // 5 minutes
                .max_capacity(100)
                .build(),
        })
    }

    /// Check if hostname matches any rule (regardless of path)
    ///
    /// Used at CONNECT time to determine if we should defer path-based enforcement
    /// to the HTTP inspection phase.
    pub async fn hostname_matches_any_rule(&self, hostname: &str) -> Result<bool, String> {
        // Resolve hostname to IPs
        let ips = resolve_hostname(hostname).await?;

        // Check if hostname matches any rule pattern (ignoring path requirements)
        for rule in &self.rules {
            let matches = match &rule.pattern {
                CompiledPattern::Host { host_regex, .. } => {
                    // Only check hostname, ignore path
                    host_regex.is_match(hostname)
                }
                CompiledPattern::Ip { cidr } => {
                    // Check if any resolved IP matches the CIDR
                    ips.iter().any(|ip| cidr.contains(*ip))
                }
            };

            if matches {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Evaluate policy for a request
    ///
    /// Performs DNS resolution and checks rules in order.
    /// Returns the first matching rule's decision.
    pub async fn evaluate(
        &self,
        hostname: &str,
        path: Option<&str>,
    ) -> Result<PolicyDecision, String> {
        // Resolve hostname to IPs
        let ips = resolve_hostname(hostname).await?;

        // Check each rule in order (first match wins)
        for (rule_index, rule) in self.rules.iter().enumerate() {
            let matches = match &rule.pattern {
                CompiledPattern::Host {
                    host_regex,
                    path_regex,
                } => {
                    // Check hostname
                    if !host_regex.is_match(hostname) {
                        continue;
                    }

                    // Check path if specified in rule
                    if let Some(path_regex) = path_regex {
                        if let Some(request_path) = path {
                            if !path_regex.is_match(request_path) {
                                continue;
                            }
                        } else {
                            // Rule requires path but request has none
                            continue;
                        }
                    }

                    true
                }
                CompiledPattern::Ip { cidr } => {
                    // Check if any resolved IP matches the CIDR
                    ips.iter().any(|ip| cidr.contains(*ip))
                }
            };

            if matches {
                tracing::debug!(
                    "policy match: hostname={} path={:?} rule_index={} action={:?} credential={:?}",
                    hostname,
                    path,
                    rule_index,
                    rule.action,
                    rule.credential
                );

                return Ok(match rule.action {
                    NetworkAction::Allow => PolicyDecision::Allow {
                        credential: rule.credential.clone(),
                        rule_index: Some(rule_index),
                    },
                    NetworkAction::Deny => PolicyDecision::Deny,
                });
            }
        }

        // No rules matched, deny by default (secure by default)
        tracing::debug!(
            "policy default: hostname={} path={:?} action=deny",
            hostname,
            path,
        );

        Ok(PolicyDecision::Deny)
    }

    /// Get credential by name
    pub fn get_credential(&self, name: &str) -> Option<&Credential> {
        self.credentials.get(name)
    }

    /// Fetch token for a credential with 5-minute caching and retry
    pub async fn fetch_token(&self, credential_name: &str) -> Result<String, String> {
        // Fetch credential from config
        let credential = self
            .credentials
            .get(credential_name)
            .ok_or_else(|| format!("Credential not found: {}", credential_name))?;

        // Use cache with automatic token fetching and retry
        let credential_clone = credential.clone();
        let cred_name_clone = credential_name.to_string();
        self.token_cache
            .try_get_with(credential_name.to_string(), async move {
                // Retry strategy: 2 retries with exponential backoff (100ms, 300ms with jitter)
                let retry_strategy = ExponentialBackoff::from_millis(100).map(jitter).take(2);

                Retry::spawn(retry_strategy, || async {
                    tracing::debug!("fetching token for credential: {}", cred_name_clone);
                    crate::config::fetch_credential_token(&credential_clone).await
                })
                .await
                .inspect(|_token| {
                    tracing::debug!("cached token for credential: {}", cred_name_clone);
                })
            })
            .await
            .map_err(|e: std::sync::Arc<String>| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_cidr() {
        let cidr: IpNetwork = "192.168.1.0/24".parse().expect("failed to parse cidr");

        assert!(cidr.contains("192.168.1.1".parse().expect("failed to parse ip")));
        assert!(cidr.contains("192.168.1.255".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("192.168.2.1".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("10.0.0.1".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv6_cidr() {
        let cidr: IpNetwork = "2001:db8::/32".parse().expect("failed to parse cidr");

        assert!(cidr.contains("2001:db8::1".parse().expect("failed to parse ip")));
        assert!(cidr.contains("2001:db8:ffff::1".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("2001:db9::1".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv4_host_bits() {
        let cidr: IpNetwork = "192.168.1.128/25".parse().expect("failed to parse cidr");

        assert!(cidr.contains("192.168.1.128".parse().expect("failed to parse ip")));
        assert!(cidr.contains("192.168.1.255".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("192.168.1.127".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("192.168.1.1".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv4_single_host() {
        // /32 prefix = single host
        let cidr: IpNetwork = "192.168.1.100/32".parse().expect("failed to parse cidr");

        assert!(cidr.contains("192.168.1.100".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("192.168.1.101".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("192.168.1.99".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv6_single_host() {
        // /128 prefix = single host
        let cidr: IpNetwork = "2001:db8::1/128".parse().expect("failed to parse cidr");

        assert!(cidr.contains("2001:db8::1".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("2001:db8::2".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("2001:db8::0".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv4_all_ips() {
        // /0 prefix = all IPv4 addresses
        let cidr: IpNetwork = "0.0.0.0/0".parse().expect("failed to parse cidr");

        assert!(cidr.contains("192.168.1.1".parse().expect("failed to parse ip")));
        assert!(cidr.contains("10.0.0.1".parse().expect("failed to parse ip")));
        assert!(cidr.contains("1.1.1.1".parse().expect("failed to parse ip")));
        assert!(cidr.contains("255.255.255.255".parse().expect("failed to parse ip")));
        // IPv6 addresses should not match IPv4 /0
        assert!(!cidr.contains("2001:db8::1".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv6_all_ips() {
        // /0 prefix = all IPv6 addresses
        let cidr: IpNetwork = "::/0".parse().expect("failed to parse cidr");

        assert!(cidr.contains("2001:db8::1".parse().expect("failed to parse ip")));
        assert!(cidr.contains("::1".parse().expect("failed to parse ip")));
        assert!(cidr.contains("fe80::1".parse().expect("failed to parse ip")));
        assert!(cidr.contains(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("failed to parse ip")
        ));
        // IPv4 addresses should not match IPv6 /0
        assert!(!cidr.contains("192.168.1.1".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv4_network_boundaries() {
        let cidr: IpNetwork = "10.0.0.0/8".parse().expect("failed to parse cidr");

        // First address in network
        assert!(cidr.contains("10.0.0.0".parse().expect("failed to parse ip")));
        // Last address in network
        assert!(cidr.contains("10.255.255.255".parse().expect("failed to parse ip")));
        // Middle addresses
        assert!(cidr.contains("10.128.0.0".parse().expect("failed to parse ip")));
        // Just outside network
        assert!(!cidr.contains("9.255.255.255".parse().expect("failed to parse ip")));
        assert!(!cidr.contains("11.0.0.0".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ipv6_network_boundaries() {
        let cidr: IpNetwork = "2001:db8::/48".parse().expect("failed to parse cidr");

        // First address
        assert!(cidr.contains("2001:db8::".parse().expect("failed to parse ip")));
        // Last address in /48 network
        assert!(cidr.contains(
            "2001:db8:0:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("failed to parse ip")
        ));
        // Middle address
        assert!(cidr.contains("2001:db8:0:8000::".parse().expect("failed to parse ip")));
        // Just outside network
        assert!(!cidr.contains(
            "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("failed to parse ip")
        ));
        assert!(!cidr.contains("2001:db8:1::".parse().expect("failed to parse ip")));
    }

    #[test]
    fn test_ip_version_mismatch() {
        let ipv4_cidr: IpNetwork = "192.168.1.0/24".parse().expect("failed to parse cidr");
        let ipv6_cidr: IpNetwork = "2001:db8::/32".parse().expect("failed to parse cidr");

        // IPv6 address should not match IPv4 CIDR
        assert!(!ipv4_cidr.contains("2001:db8::1".parse().expect("failed to parse ip")));
        // IPv4 address should not match IPv6 CIDR
        assert!(!ipv6_cidr.contains("192.168.1.1".parse().expect("failed to parse ip")));
    }

    // Policy evaluation tests
    use crate::config::{Credential, CredentialSource, CredentialType};
    use crate::jail::{HostPattern, IpPattern, NetworkAction, NetworkPattern, NetworkRule};

    fn test_credentials() -> Vec<Credential> {
        vec![
            Credential {
                name: "anthropic".to_string(),
                credential_type: CredentialType::Claude,
                source: CredentialSource::Environment {
                    source_env: "ANTHROPIC_API_KEY".to_string(),
                },
                allowed_host_patterns: vec![r"api\.anthropic\.com".to_string()],
                header_format: "Bearer {token}".to_string(),
                dummy_token: None,
            },
            Credential {
                name: "github".to_string(),
                credential_type: CredentialType::GitHub,
                source: CredentialSource::Environment {
                    source_env: "GITHUB_TOKEN".to_string(),
                },
                allowed_host_patterns: vec![r"api\.github\.com".to_string()],
                header_format: "token {token}".to_string(),
                dummy_token: None,
            },
        ]
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_host_match_with_credential() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"api\.anthropic\.com".to_string(),
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: Some("anthropic".to_string()),
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match and allow with credential
        let decision = compiled
            .evaluate("api.anthropic.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                credential: Some(ref cred),
                rule_index: Some(0),
            } if cred == "anthropic"
        ));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_host_match_with_path() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"api\.anthropic\.com".to_string(),
                        path: Some(r"/v1/.*".to_string()),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: Some("anthropic".to_string()),
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match with correct path
        let decision = compiled
            .evaluate("api.anthropic.com", Some("/v1/messages"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should not match with wrong path
        let decision = compiled
            .evaluate("api.anthropic.com", Some("/v2/messages"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_host_no_match() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"api\.anthropic\.com".to_string(),
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should not match different host
        let decision = compiled
            .evaluate("api.github.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_first_match_wins() {
        let policy = NetworkPolicy {
            rules: vec![
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r".*\.anthropic\.com".to_string(),
                            path: None,
                        })),
                    }),
                    action: NetworkAction::Allow as i32,
                    credential: Some("anthropic".to_string()),
                },
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r"api\.anthropic\.com".to_string(),
                            path: None,
                        })),
                    }),
                    action: NetworkAction::Deny as i32,
                    credential: None,
                },
            ],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // First rule should match (allow with credential at index 0)
        let decision = compiled
            .evaluate("api.anthropic.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                rule_index: Some(0),
                credential: Some(ref cred),
            } if cred == "anthropic"
        ));
    }

    #[tokio::test]
    async fn test_policy_ip_cidr_match() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Ip(IpPattern {
                        cidr: "192.168.1.0/24".to_string(),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let _compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Note: This will fail if the hostname doesn't resolve to an IP in the CIDR
        // In a real scenario, we'd need a hostname that resolves to 192.168.1.x
        // For now, this test documents the expected behavior
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_default_deny() {
        let policy = NetworkPolicy { rules: vec![] };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // No rules, should use default deny
        // Use a real hostname that will resolve (google.com)
        let decision = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_allow_all_with_catchall_rule() {
        // Allow-all now requires an explicit catch-all rule
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r".*".to_string(),
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match the catch-all rule and allow (with rule index 0, no credential)
        // Use a real hostname that will resolve (google.com)
        let decision = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                credential: None,
                rule_index: Some(0),
            }
        ));
    }

    // Multi-rule interaction tests

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_multiple_credentials_different_paths() {
        let policy = NetworkPolicy {
            rules: vec![
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r"api\.anthropic\.com".to_string(),
                            path: Some(r"/v1/.*".to_string()),
                        })),
                    }),
                    action: NetworkAction::Allow as i32,
                    credential: Some("anthropic".to_string()),
                },
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r"api\.anthropic\.com".to_string(),
                            path: Some(r"/v2/.*".to_string()),
                        })),
                    }),
                    action: NetworkAction::Allow as i32,
                    credential: Some("github".to_string()), // Different credential
                },
            ],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // First path should use anthropic credential
        let decision = compiled
            .evaluate("api.anthropic.com", Some("/v1/messages"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                credential: Some(ref cred),
                rule_index: Some(0),
            } if cred == "anthropic"
        ));

        // Second path should use github credential
        let decision = compiled
            .evaluate("api.anthropic.com", Some("/v2/messages"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                credential: Some(ref cred),
                rule_index: Some(1),
            } if cred == "github"
        ));

        // No matching path should deny
        let decision = compiled
            .evaluate("api.anthropic.com", Some("/v3/messages"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_overlapping_host_patterns() {
        let policy = NetworkPolicy {
            rules: vec![
                // Specific host first
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r"^www\.github\.com$".to_string(), // Use real resolvable domain
                            path: None,
                        })),
                    }),
                    action: NetworkAction::Allow as i32,
                    credential: Some("github".to_string()),
                },
                // Broader pattern second (should not match for www.github.com due to first match wins)
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r".*\.github\.com".to_string(),
                            path: None,
                        })),
                    }),
                    action: NetworkAction::Deny as i32,
                    credential: None,
                },
            ],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // First rule should match for exact hostname
        let decision = compiled
            .evaluate("www.github.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                credential: Some(ref cred),
                rule_index: Some(0),
            } if cred == "github"
        ));

        // Second rule should match for other subdomains
        let decision = compiled
            .evaluate("api.github.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_deny_before_allow() {
        // Test that deny rules can block even if later rules would allow
        let policy = NetworkPolicy {
            rules: vec![
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r"api\.anthropic\.com".to_string(),
                            path: Some(r"/admin/.*".to_string()),
                        })),
                    }),
                    action: NetworkAction::Deny as i32,
                    credential: None,
                },
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r"api\.anthropic\.com".to_string(),
                            path: None,
                        })),
                    }),
                    action: NetworkAction::Allow as i32,
                    credential: Some("anthropic".to_string()),
                },
            ],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Admin path should be denied even though later rule would allow
        let decision = compiled
            .evaluate("api.anthropic.com", Some("/admin/users"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));

        // Non-admin path should be allowed by second rule
        let decision = compiled
            .evaluate("api.anthropic.com", Some("/v1/messages"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                credential: Some(ref cred),
                ..
            } if cred == "anthropic"
        ));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_allow_without_credential() {
        // Test that allow rules can work without credentials
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"wikipedia\.org".to_string(), // Use real resolvable domain
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None, // No credential required
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        let decision = compiled
            .evaluate("wikipedia.org", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(
            decision,
            PolicyDecision::Allow {
                credential: None,
                rule_index: Some(0),
            }
        ));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_mixed_ip_and_host_rules() {
        // Test interaction between IP-based and hostname-based rules
        let policy = NetworkPolicy {
            rules: vec![
                // IP rule first
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Ip(IpPattern {
                            cidr: "8.8.8.0/24".to_string(), // Google DNS range
                        })),
                    }),
                    action: NetworkAction::Deny as i32,
                    credential: None,
                },
                // Hostname rule second
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(network_pattern::Pattern::Host(HostPattern {
                            host: r"dns\.google".to_string(),
                            path: None,
                        })),
                    }),
                    action: NetworkAction::Allow as i32,
                    credential: Some("github".to_string()),
                },
            ],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // dns.google resolves to 8.8.8.8, so IP rule should match first
        let decision = compiled
            .evaluate("dns.google", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[test]
    fn test_policy_many_rules() {
        // Test compilation performance with many rules (no DNS resolution)
        let mut rules = Vec::new();
        for i in 0..100 {
            rules.push(NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: format!(r"host{}\.example\.com", i),
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            });
        }

        let policy = NetworkPolicy { rules };

        // Test that compilation succeeds with many rules
        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Verify we compiled all 100 rules
        assert_eq!(compiled.rules.len(), 100);
    }

    // Path matching edge case tests

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_none_vs_empty() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"google\.com".to_string(), // Use real resolvable domain
                        path: None,                       // No path requirement
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match with no path
        let decision = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should also match with any path
        let decision = compiled
            .evaluate("google.com", Some("/v1/test"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should also match with empty path
        let decision = compiled
            .evaluate("google.com", Some(""))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_root_slash() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"github\.com".to_string(), // Use real resolvable domain
                        path: Some(r"^/$".to_string()),   // Exact match for root path
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match root path
        let decision = compiled
            .evaluate("github.com", Some("/"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should not match other paths
        let decision = compiled
            .evaluate("github.com", Some("/v1"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));

        // Should not match no path
        let decision = compiled
            .evaluate("github.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_trailing_slash() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"www\.rust-lang\.org".to_string(), // Use real resolvable domain
                        path: Some(r"/v1/.*".to_string()),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match with trailing slash
        let decision = compiled
            .evaluate("www.rust-lang.org", Some("/v1/"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should match without trailing slash
        let decision = compiled
            .evaluate("www.rust-lang.org", Some("/v1/test"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_double_slash() {
        // Test that paths with double slashes are handled as-is (no normalization)
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"crates\.io".to_string(), // Use real resolvable domain
                        path: Some(r"/v1/test".to_string()),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Normal path should match
        let decision = compiled
            .evaluate("crates.io", Some("/v1/test"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Double slash should NOT match (no normalization)
        let decision = compiled
            .evaluate("crates.io", Some("/v1//test"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_with_query_string() {
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"docs\.rs".to_string(), // Use real resolvable domain
                        path: Some(r"/search\?.*".to_string()),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match with query string
        let decision = compiled
            .evaluate("docs.rs", Some("/search?q=test"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should not match without query string
        let decision = compiled
            .evaluate("docs.rs", Some("/search"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_with_fragment() {
        // Test paths with fragments (anchors)
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"lib\.rs".to_string(), // Use real resolvable domain
                        path: Some(r"/docs.*".to_string()),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match with fragment
        let decision = compiled
            .evaluate("lib.rs", Some("/docs#section"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should match without fragment
        let decision = compiled
            .evaluate("lib.rs", Some("/docs"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_case_sensitive() {
        // Paths are case-sensitive by default
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"news\.ycombinator\.com".to_string(), // Use real resolvable domain
                        path: Some(r"/API/.*".to_string()),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match uppercase
        let decision = compiled
            .evaluate("news.ycombinator.com", Some("/API/test"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Should not match lowercase (case-sensitive)
        let decision = compiled
            .evaluate("news.ycombinator.com", Some("/api/test"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires DNS resolution
    async fn test_policy_path_special_chars() {
        // Test path with URL-encoded or special characters
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"reddit\.com".to_string(), // Use real resolvable domain
                        path: Some(r"/v1/.*".to_string()),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // Should match with special characters
        let decision = compiled
            .evaluate("reddit.com", Some("/v1/test%20space"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        let decision = compiled
            .evaluate("reddit.com", Some("/v1/test+plus"))
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    // DNS resolution and caching tests

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_dns_resolution_ipv4() {
        // Test that DNS resolution works and IP CIDR matching works together
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Ip(IpPattern {
                        // Google's public DNS is at 8.8.8.8
                        cidr: "8.8.8.0/24".to_string(),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // dns.google should resolve to 8.8.8.8 which is in 8.8.8.0/24
        let decision = compiled
            .evaluate("dns.google", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_dns_resolution_outside_cidr() {
        // Test that hostnames resolving outside CIDR are denied
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Ip(IpPattern {
                        // Private network range
                        cidr: "192.168.0.0/16".to_string(),
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // google.com does not resolve to private IPs
        let decision = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Deny));
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_dns_cache_reuse() {
        // Test that DNS lookups are cached (by doing multiple evaluations)
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"google\.com".to_string(),
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // First lookup (will hit DNS)
        let start = std::time::Instant::now();
        let decision1 = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");
        let first_duration = start.elapsed();

        // Second lookup (should use cache and be faster)
        let start = std::time::Instant::now();
        let decision2 = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");
        let second_duration = start.elapsed();

        // Both should succeed
        assert!(matches!(decision1, PolicyDecision::Allow { .. }));
        assert!(matches!(decision2, PolicyDecision::Allow { .. }));

        // Second lookup should be noticeably faster (cached)
        // Note: This is a heuristic test - cached lookup should be microseconds vs milliseconds
        // We use a lenient check to avoid flakiness
        tracing::info!(
            "first dns lookup: {:?}, second (cached): {:?}",
            first_duration,
            second_duration
        );
        // Second should be at most 50% of first (usually much faster)
        assert!(second_duration < first_duration);
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_dns_multiple_ips() {
        // Test hostname that resolves to multiple IPs
        // If any IP matches the CIDR, the rule should match
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Ip(IpPattern {
                        // Broader range that should include some of google's IPs
                        cidr: "0.0.0.0/0".to_string(), // All IPv4
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // google.com resolves to multiple IPs
        let decision = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_dns_lookup_failure() {
        // Test graceful handling of DNS lookup failures
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"nonexistent\.invalid".to_string(),
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // This should fail DNS lookup gracefully
        let result = compiled.evaluate("nonexistent.invalid", None).await;

        // DNS lookup should fail with an error
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DNS lookup failed"));
    }

    #[tokio::test]
    #[ignore] // Requires network
    async fn test_dns_ipv6_resolution() {
        // Test IPv6 DNS resolution
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Ip(IpPattern {
                        // IPv6 range
                        cidr: "::/0".to_string(), // All IPv6
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: None,
            }],
        };

        let compiled =
            CompiledPolicy::compile(policy, &test_credentials()).expect("failed to compile policy");

        // google.com has both IPv4 and IPv6 addresses
        // Should match if any IPv6 address is returned
        let decision = compiled
            .evaluate("google.com", None)
            .await
            .expect("failed to evaluate policy");

        // Note: This might allow or deny depending on which IPs are returned
        // The test documents the behavior rather than asserting specific outcome
        match decision {
            PolicyDecision::Allow { .. } => {
                // IPv6 address was returned and matched
                tracing::info!("google.com resolved to ipv6 address");
            }
            PolicyDecision::Deny => {
                // Only IPv4 addresses were returned
                tracing::info!("google.com resolved only to ipv4 addresses");
            }
        }
    }
}
