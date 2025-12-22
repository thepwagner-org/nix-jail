//! Input validation for security-critical fields.
//!
//! These functions return tonic::Status directly for gRPC error handling.
#![allow(clippy::result_large_err)] // tonic::Status is 176 bytes, acceptable for gRPC errors

use crate::config::Credential;
use crate::jail::{network_pattern, HostPattern, IpPattern, NetworkPolicy, NetworkRule};
use ipnetwork::IpNetwork;
use regex::RegexBuilder;
use std::collections::HashSet;
use std::path::Path;
use tonic::Status;

/// Maximum compiled regex size to prevent ReDoS attacks
const MAX_REGEX_SIZE: usize = 10_000;

// Input validation limits
const MAX_SCRIPT_LEN: usize = 10240;
const MAX_REPO_URL_LEN: usize = 2048;
const MAX_PATH_LEN: usize = 1024;
const MAX_REF_LEN: usize = 256;

/// Validate script content
pub fn validate_script(script: &str) -> Result<(), Status> {
    if script.is_empty() {
        return Err(Status::invalid_argument("Script cannot be empty"));
    }

    if script.len() > MAX_SCRIPT_LEN {
        return Err(Status::invalid_argument(format!(
            "Script too long (max {} characters)",
            MAX_SCRIPT_LEN
        )));
    }

    Ok(())
}

/// Validate repository URL
pub fn validate_repo(repo: &str) -> Result<(), Status> {
    if !repo.starts_with("https://") {
        return Err(Status::invalid_argument(
            "Repository must be a valid HTTPS URL",
        ));
    }

    if repo.len() > MAX_REPO_URL_LEN {
        return Err(Status::invalid_argument(format!(
            "Repository URL too long (max {} characters)",
            MAX_REPO_URL_LEN
        )));
    }

    Ok(())
}

/// Validate path to prevent path traversal
///
/// This performs multiple security checks:
/// - Allows empty paths (empty path means use repo root)
/// - Rejects absolute paths (must be relative)
/// - Rejects path traversal attempts (..)
/// - Validates that the normalized path doesn't escape the base directory
/// - Enforces length limits
pub fn validate_path(path: &str) -> Result<(), Status> {
    if path.is_empty() {
        return Ok(());
    }

    // Reject absolute paths (should be relative within repo)
    if path.starts_with('/') {
        return Err(Status::invalid_argument(
            "Path must be relative (no leading /)",
        ));
    }

    if path.len() > MAX_PATH_LEN {
        return Err(Status::invalid_argument(format!(
            "Path too long (max {} characters)",
            MAX_PATH_LEN
        )));
    }

    // Prevent path traversal by checking for ".." components
    let path_obj = Path::new(path);
    for component in path_obj.components() {
        if let std::path::Component::ParentDir = component {
            return Err(Status::invalid_argument("Path traversal not allowed (..)"));
        }
    }

    Ok(())
}

/// Validate git ref (branch, tag, or commit SHA)
///
/// Security checks:
/// - Prevents command injection via shell metacharacters
/// - Enforces length limits
/// - Allows standard git ref formats
pub fn validate_ref(git_ref: &str) -> Result<(), Status> {
    if git_ref.is_empty() {
        // Empty ref is allowed (uses default branch)
        return Ok(());
    }

    // Length limit
    if git_ref.len() > MAX_REF_LEN {
        return Err(Status::invalid_argument(format!(
            "Git ref too long (max {} characters)",
            MAX_REF_LEN
        )));
    }

    // Check for shell metacharacters to prevent command injection
    // Git refs can contain: alphanumeric, -, _, /, .
    // Also allow full 40-char hex strings for commit SHAs
    let is_valid_sha = git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit());
    let has_safe_chars = git_ref
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.');

    if !is_valid_sha && !has_safe_chars {
        return Err(Status::invalid_argument(
            "Git ref contains invalid characters (allowed: alphanumeric, -, _, /, .)",
        ));
    }

    // Prevent path traversal in ref names
    if git_ref.contains("..") {
        return Err(Status::invalid_argument(
            "Git ref cannot contain '..' (path traversal not allowed)",
        ));
    }

    // Reject refs starting or ending with . or / (invalid git refs)
    if git_ref.starts_with('.') || git_ref.ends_with('.') {
        return Err(Status::invalid_argument(
            "Git ref cannot start or end with '.'",
        ));
    }

    if git_ref.starts_with('/') || git_ref.ends_with('/') {
        return Err(Status::invalid_argument(
            "Git ref cannot start or end with '/'",
        ));
    }

    Ok(())
}

/// Validate nixpkgs version string
///
/// Security checks:
/// - Prevents URL injection in nixpkgs archive URL construction
/// - Allows branch names (nixos-24.05, nixpkgs-unstable)
/// - Allows 40-character commit SHAs
/// - Rejects shell metacharacters
pub fn validate_nixpkgs_version(version: &str) -> Result<(), Status> {
    if version.is_empty() {
        return Err(Status::invalid_argument("nixpkgs version cannot be empty"));
    }

    // Check for valid 40-char commit SHA
    let is_valid_sha = version.len() == 40 && version.chars().all(|c| c.is_ascii_hexdigit());

    // Check for safe characters (alphanumeric, hyphen, dot, underscore)
    let has_safe_chars = version
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.' || c == '_');

    if !is_valid_sha && !has_safe_chars {
        return Err(Status::invalid_argument(
            "nixpkgs version contains invalid characters (allowed: alphanumeric, -, _, .)",
        ));
    }

    Ok(())
}

/// NetworkPolicy validation error
#[derive(Debug)]
pub enum NetworkPolicyError {
    InvalidRegex { pattern: String, error: String },
    InvalidCidr { cidr: String, error: String },
    UnknownCredential { credential: String },
    MissingPattern,
}

impl std::fmt::Display for NetworkPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkPolicyError::InvalidRegex { pattern, error } => {
                write!(f, "Invalid regex pattern '{}': {}", pattern, error)
            }
            NetworkPolicyError::InvalidCidr { cidr, error } => {
                write!(f, "Invalid CIDR '{}': {}", cidr, error)
            }
            NetworkPolicyError::UnknownCredential { credential } => {
                write!(
                    f,
                    "Unknown credential '{}' (not in server config)",
                    credential
                )
            }
            NetworkPolicyError::MissingPattern => {
                write!(f, "NetworkRule missing pattern")
            }
        }
    }
}

impl std::error::Error for NetworkPolicyError {}

impl From<NetworkPolicyError> for Status {
    fn from(err: NetworkPolicyError) -> Self {
        Status::invalid_argument(err.to_string())
    }
}

/// Validate a NetworkPolicy against available credentials
pub fn validate_network_policy(
    policy: &NetworkPolicy,
    credentials: &[Credential],
) -> Result<(), NetworkPolicyError> {
    let available_credentials: HashSet<String> =
        credentials.iter().map(|c| c.name.clone()).collect();

    for rule in &policy.rules {
        validate_network_rule(rule, &available_credentials)?;
    }

    Ok(())
}

/// Validate a single NetworkRule
fn validate_network_rule(
    rule: &NetworkRule,
    available_credentials: &HashSet<String>,
) -> Result<(), NetworkPolicyError> {
    // Validate pattern
    let pattern = rule
        .pattern
        .as_ref()
        .ok_or(NetworkPolicyError::MissingPattern)?;
    match &pattern.pattern {
        Some(network_pattern::Pattern::Host(host_pattern)) => {
            validate_host_pattern(host_pattern)?;
        }
        Some(network_pattern::Pattern::Ip(ip_pattern)) => {
            validate_ip_pattern(ip_pattern)?;
        }
        None => return Err(NetworkPolicyError::MissingPattern),
    }

    // Validate credential reference if present
    if let Some(credential) = &rule.credential {
        if !available_credentials.contains(credential) {
            return Err(NetworkPolicyError::UnknownCredential {
                credential: credential.clone(),
            });
        }
    }

    Ok(())
}

/// Validate a HostPattern (regex for host and optional path)
fn validate_host_pattern(pattern: &HostPattern) -> Result<(), NetworkPolicyError> {
    // Validate host regex compiles with size limit to prevent ReDoS
    let _ = RegexBuilder::new(&pattern.host)
        .size_limit(MAX_REGEX_SIZE)
        .build()
        .map_err(|e| NetworkPolicyError::InvalidRegex {
            pattern: pattern.host.clone(),
            error: e.to_string(),
        })?;

    // Validate path regex if present
    if let Some(path) = &pattern.path {
        let _ = RegexBuilder::new(path)
            .size_limit(MAX_REGEX_SIZE)
            .build()
            .map_err(|e| NetworkPolicyError::InvalidRegex {
                pattern: path.clone(),
                error: e.to_string(),
            })?;
    }

    Ok(())
}

/// Validate an IpPattern (CIDR notation)
fn validate_ip_pattern(pattern: &IpPattern) -> Result<(), NetworkPolicyError> {
    if !pattern.cidr.contains('/') {
        return Err(NetworkPolicyError::InvalidCidr {
            cidr: pattern.cidr.clone(),
            error: "CIDR must be in format 'ip/prefix' (e.g., '192.168.1.0/24')".to_string(),
        });
    }

    let _ = pattern
        .cidr
        .parse::<IpNetwork>()
        .map_err(|e| NetworkPolicyError::InvalidCidr {
            cidr: pattern.cidr.clone(),
            error: e.to_string(),
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_repo_valid() {
        assert!(validate_repo("https://github.com/test/repo").is_ok());
        assert!(validate_repo("https://gitlab.com/test/repo").is_ok());
    }

    #[test]
    fn test_validate_repo_empty() {
        assert!(validate_repo("").is_err());
    }

    #[test]
    fn test_validate_repo_invalid_scheme() {
        // Only HTTPS is allowed
        assert!(validate_repo("http://gitlab.com/test/repo").is_err());
        assert!(validate_repo("git@github.com:test/repo.git").is_err());
        assert!(validate_repo("file:///etc/passwd").is_err());
        assert!(validate_repo("ftp://example.com/repo").is_err());
        assert!(validate_repo("invalid-url").is_err());
    }

    #[test]
    fn test_validate_repo_too_long() {
        let long_url = format!("https://github.com/{}", "a".repeat(3000));
        assert!(validate_repo(&long_url).is_err());
    }

    #[test]
    fn test_validate_path_valid() {
        assert!(validate_path("some/path").is_ok());
        assert!(validate_path("a").is_ok());
        assert!(validate_path("deep/nested/path/to/file").is_ok());
        assert!(validate_path(".").is_ok()); // Default path (current directory)
    }

    #[test]
    fn test_validate_path_empty() {
        // Empty path is allowed - it means use the repo root
        assert!(validate_path("").is_ok());
    }

    #[test]
    fn test_validate_path_traversal() {
        // Security: path traversal attempts should be rejected
        assert!(validate_path("../etc/passwd").is_err());
        assert!(validate_path("path/../etc").is_err());
        assert!(validate_path("..").is_err());
        assert!(validate_path("a/../../b").is_err());
    }

    #[test]
    fn test_validate_path_absolute() {
        // Security: absolute paths should be rejected
        assert!(validate_path("/etc/passwd").is_err());
        assert!(validate_path("/absolute/path").is_err());
    }

    #[test]
    fn test_validate_path_too_long() {
        let long_path = "a".repeat(2000);
        assert!(validate_path(&long_path).is_err());
    }

    #[test]
    fn test_validate_path_current_dir() {
        // "." and "./" should be valid
        assert!(validate_path(".").is_ok());
        assert!(validate_path("./subdir").is_ok());
    }

    #[test]
    fn test_validate_script_valid() {
        assert!(validate_script("Build this package").is_ok());
        assert!(validate_script("x").is_ok());
    }

    #[test]
    fn test_validate_script_empty() {
        assert!(validate_script("").is_err());
    }

    #[test]
    fn test_validate_script_too_long() {
        let long_prompt = "a".repeat(15000);
        assert!(validate_script(&long_prompt).is_err());
    }

    #[test]
    fn test_validate_script_max_length() {
        let max_prompt = "a".repeat(10240);
        assert!(validate_script(&max_prompt).is_ok());

        let too_long_prompt = "a".repeat(10241);
        assert!(validate_script(&too_long_prompt).is_err());
    }

    // NetworkPolicy validation tests

    use crate::config::{Credential, CredentialSource, CredentialType};
    use crate::jail::{NetworkAction, NetworkPattern};

    fn test_credentials() -> Vec<Credential> {
        vec![Credential {
            name: "anthropic".to_string(),
            credential_type: CredentialType::Claude,
            source: CredentialSource::Keychain {
                keychain_service: "test".to_string(),
                keychain_account: None,
            },
            allowed_host_patterns: vec!["api\\.anthropic\\.com".to_string()],
            header_format: "Bearer {token}".to_string(),
            dummy_token: None,
        }]
    }

    #[test]
    fn test_valid_host_pattern() {
        let pattern = HostPattern {
            host: r"api\.anthropic\.com".to_string(),
            path: Some(r"/v1/.*".to_string()),
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_invalid_host_regex() {
        let pattern = HostPattern {
            host: r"[invalid(".to_string(),
            path: None,
        };
        assert!(matches!(
            validate_host_pattern(&pattern),
            Err(NetworkPolicyError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn test_host_regex_wildcard_subdomain() {
        // Wildcard pattern for any subdomain of example.com
        let pattern = HostPattern {
            host: r".*\.example\.com".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_case_sensitive() {
        // Regex is case-sensitive by default
        let pattern = HostPattern {
            host: r"API\.example\.com".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_case_insensitive() {
        // Case-insensitive flag
        let pattern = HostPattern {
            host: r"(?i)api\.example\.com".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_unicode() {
        // Unicode domain names (IDN)
        let pattern = HostPattern {
            host: r"münchen\.example\.com".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_escaped_special_chars() {
        // Test properly escaped special characters
        let pattern = HostPattern {
            host: r"api-v1\.example\.com".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_alternation() {
        // Multiple hosts using alternation
        let pattern = HostPattern {
            host: r"(api|www|cdn)\.example\.com".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_anchored() {
        // Explicitly anchored pattern
        let pattern = HostPattern {
            host: r"^api\.example\.com$".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_path_regex_valid() {
        let pattern = HostPattern {
            host: r"api\.example\.com".to_string(),
            path: Some(r"/v[0-9]+/.*".to_string()),
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_path_regex_invalid() {
        let pattern = HostPattern {
            host: r"api\.example\.com".to_string(),
            path: Some(r"[unclosed".to_string()),
        };
        assert!(matches!(
            validate_host_pattern(&pattern),
            Err(NetworkPolicyError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn test_path_regex_empty() {
        // None vs Some("") - both should be valid
        let pattern1 = HostPattern {
            host: r"api\.example\.com".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern1).is_ok());

        let pattern2 = HostPattern {
            host: r"api\.example\.com".to_string(),
            path: Some("".to_string()),
        };
        assert!(validate_host_pattern(&pattern2).is_ok());
    }

    #[test]
    fn test_path_regex_query_string() {
        // Pattern that matches path with query strings
        let pattern = HostPattern {
            host: r"api\.example\.com".to_string(),
            path: Some(r"/search\?.*".to_string()),
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_simple_redos_pattern_allowed() {
        // Simple ReDoS patterns that don't exceed size limit still compile
        // The size limit primarily protects against pathologically large patterns
        let pattern = HostPattern {
            host: r"(a+)+b".to_string(),
            path: None,
        };
        assert!(validate_host_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_host_regex_exceeds_size_limit() {
        // Pattern that exceeds compiled regex size limit
        let huge_pattern = format!("({})+", "a".repeat(10000));
        let pattern = HostPattern {
            host: huge_pattern,
            path: None,
        };
        assert!(matches!(
            validate_host_pattern(&pattern),
            Err(NetworkPolicyError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn test_valid_ipv4_cidr() {
        let pattern = IpPattern {
            cidr: "192.168.1.0/24".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_valid_ipv6_cidr() {
        let pattern = IpPattern {
            cidr: "2001:db8::/32".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_invalid_cidr_format() {
        let pattern = IpPattern {
            cidr: "192.168.1.0".to_string(),
        };
        assert!(matches!(
            validate_ip_pattern(&pattern),
            Err(NetworkPolicyError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn test_invalid_cidr_prefix() {
        let pattern = IpPattern {
            cidr: "192.168.1.0/33".to_string(),
        };
        assert!(matches!(
            validate_ip_pattern(&pattern),
            Err(NetworkPolicyError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn test_invalid_ipv6_cidr_prefix() {
        let pattern = IpPattern {
            cidr: "2001:db8::/129".to_string(),
        };
        assert!(matches!(
            validate_ip_pattern(&pattern),
            Err(NetworkPolicyError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn test_cidr_non_zero_host_bits_ipv4() {
        // Note: ipnetwork crate accepts non-zero host bits and masks them
        // "192.168.1.1/24" is parsed as "192.168.1.0/24"
        // This is acceptable behavior - the network is still correctly identified
        let pattern = IpPattern {
            cidr: "192.168.1.1/24".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_cidr_non_zero_host_bits_ipv6() {
        // Note: ipnetwork crate accepts non-zero host bits and masks them
        // "2001:db8::1/32" is parsed as "2001:db8::/32"
        let pattern = IpPattern {
            cidr: "2001:db8::1/32".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_cidr_malformed_ip() {
        let pattern = IpPattern {
            cidr: "256.256.256.256/24".to_string(),
        };
        assert!(matches!(
            validate_ip_pattern(&pattern),
            Err(NetworkPolicyError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn test_cidr_malformed_prefix() {
        let pattern = IpPattern {
            cidr: "192.168.1.0/abc".to_string(),
        };
        assert!(matches!(
            validate_ip_pattern(&pattern),
            Err(NetworkPolicyError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn test_cidr_negative_prefix() {
        let pattern = IpPattern {
            cidr: "192.168.1.0/-1".to_string(),
        };
        assert!(matches!(
            validate_ip_pattern(&pattern),
            Err(NetworkPolicyError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn test_cidr_empty_string() {
        let pattern = IpPattern {
            cidr: "".to_string(),
        };
        assert!(matches!(
            validate_ip_pattern(&pattern),
            Err(NetworkPolicyError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn test_cidr_valid_single_host_ipv4() {
        // /32 is valid for single host
        let pattern = IpPattern {
            cidr: "192.168.1.100/32".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_cidr_valid_single_host_ipv6() {
        // /128 is valid for single host
        let pattern = IpPattern {
            cidr: "2001:db8::1/128".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_cidr_valid_all_ipv4() {
        // 0.0.0.0/0 is valid (all IPv4 addresses)
        let pattern = IpPattern {
            cidr: "0.0.0.0/0".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_cidr_valid_all_ipv6() {
        // ::/0 is valid (all IPv6 addresses)
        let pattern = IpPattern {
            cidr: "::/0".to_string(),
        };
        assert!(validate_ip_pattern(&pattern).is_ok());
    }

    #[test]
    fn test_unknown_credential() {
        let credentials = test_credentials();
        let policy = NetworkPolicy {
            rules: vec![NetworkRule {
                pattern: Some(NetworkPattern {
                    pattern: Some(network_pattern::Pattern::Host(HostPattern {
                        host: r"github\.com".to_string(),
                        path: None,
                    })),
                }),
                action: NetworkAction::Allow as i32,
                credential: Some("github".to_string()),
            }],
        };

        assert!(matches!(
            validate_network_policy(&policy, &credentials),
            Err(NetworkPolicyError::UnknownCredential { .. })
        ));
    }

    #[test]
    fn test_valid_network_policy() {
        let credentials = test_credentials();
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

        assert!(validate_network_policy(&policy, &credentials).is_ok());
    }

    // Git ref validation tests

    #[test]
    fn test_validate_ref_empty() {
        // Empty ref is allowed (uses default branch)
        assert!(validate_ref("").is_ok());
    }

    #[test]
    fn test_validate_ref_branch() {
        assert!(validate_ref("main").is_ok());
        assert!(validate_ref("develop").is_ok());
        assert!(validate_ref("feature/foo").is_ok());
        assert!(validate_ref("feature/bar-baz").is_ok());
        assert!(validate_ref("release/v1.2.3").is_ok());
    }

    #[test]
    fn test_validate_ref_tag() {
        assert!(validate_ref("v1.0.0").is_ok());
        assert!(validate_ref("v1.2.3-beta").is_ok());
        assert!(validate_ref("release-2024.01").is_ok());
    }

    #[test]
    fn test_validate_ref_commit_sha() {
        assert!(validate_ref("a1b2c3d4e5f6789012345678901234567890abcd").is_ok());
        assert!(validate_ref("0123456789abcdef0123456789abcdef01234567").is_ok());
    }

    #[test]
    fn test_validate_ref_invalid_chars() {
        // Shell metacharacters should be rejected
        assert!(validate_ref("main; rm -rf /").is_err());
        assert!(validate_ref("main && ls").is_err());
        assert!(validate_ref("main | cat").is_err());
        assert!(validate_ref("main`whoami`").is_err());
        assert!(validate_ref("main$(whoami)").is_err());
        assert!(validate_ref("main&").is_err());
        assert!(validate_ref("main>file").is_err());
        assert!(validate_ref("main<file").is_err());
    }

    #[test]
    fn test_validate_ref_path_traversal() {
        assert!(validate_ref("..").is_err());
        assert!(validate_ref("../etc/passwd").is_err());
        assert!(validate_ref("feature/../main").is_err());
    }

    #[test]
    fn test_validate_ref_invalid_start_end() {
        assert!(validate_ref(".hidden").is_err());
        assert!(validate_ref("branch.").is_err());
        assert!(validate_ref("/absolute").is_err());
        assert!(validate_ref("trailing/").is_err());
    }

    #[test]
    fn test_validate_ref_too_long() {
        let long_ref = "a".repeat(300);
        assert!(validate_ref(&long_ref).is_err());
    }

    #[test]
    fn test_validate_ref_max_length() {
        let max_ref = "a".repeat(256);
        assert!(validate_ref(&max_ref).is_ok());

        let too_long = "a".repeat(257);
        assert!(validate_ref(&too_long).is_err());
    }

    // nixpkgs version validation tests

    #[test]
    fn test_validate_nixpkgs_version_branch() {
        assert!(validate_nixpkgs_version("nixos-24.05").is_ok());
        assert!(validate_nixpkgs_version("nixpkgs-unstable").is_ok());
        assert!(validate_nixpkgs_version("nixos-unstable").is_ok());
        assert!(validate_nixpkgs_version("master").is_ok());
    }

    #[test]
    fn test_validate_nixpkgs_version_sha() {
        assert!(validate_nixpkgs_version("a1b2c3d4e5f6789012345678901234567890abcd").is_ok());
        assert!(validate_nixpkgs_version("0123456789abcdef0123456789abcdef01234567").is_ok());
    }

    #[test]
    fn test_validate_nixpkgs_version_empty() {
        assert!(validate_nixpkgs_version("").is_err());
    }

    #[test]
    fn test_validate_nixpkgs_version_invalid_chars() {
        // Shell metacharacters should be rejected
        assert!(validate_nixpkgs_version("nixos; rm -rf /").is_err());
        assert!(validate_nixpkgs_version("nixos && ls").is_err());
        assert!(validate_nixpkgs_version("nixos | cat").is_err());
        assert!(validate_nixpkgs_version("nixos`whoami`").is_err());
        assert!(validate_nixpkgs_version("nixos$(whoami)").is_err());
        // URL injection
        assert!(validate_nixpkgs_version("nixos/../../../etc/passwd").is_err());
    }
}
