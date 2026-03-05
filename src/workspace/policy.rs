//! Proxy configuration generation for jobs
//!
//! Creates alice TOML config files that configure the MITM proxy with
//! network policies and credentials. The config file is stored outside
//! the sandbox (in job_dir.base) so the sandboxed process cannot access it.

use crate::config::{Credential, CredentialSource};
use crate::jail::NetworkPolicy;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Generate a cryptographically random password for proxy authentication
pub fn generate_proxy_password() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

/// Result of writing a proxy config — includes the config path and any
/// environment variables that must be set on the alice process (for credentials
/// that need to be resolved at orchestrator level, like keychain or inline).
#[derive(Debug)]
pub struct ProxyConfigResult {
    /// Path to the alice TOML config file
    pub config_path: PathBuf,
    /// Environment variables to set on the alice process
    /// (credential env vars, proxy password, etc.)
    pub env_vars: HashMap<String, String>,
    /// Port alice will listen on (extracted from listen_addr)
    pub port: u16,
    /// Proxy username for HTTP Basic Auth
    pub proxy_username: Option<String>,
    /// Proxy password for HTTP Basic Auth
    pub proxy_password: Option<String>,
    /// Port for alice's observability metrics endpoint (if enabled)
    pub metrics_port: Option<u16>,
}

/// Write alice proxy configuration file to the job's base directory
///
/// The config file is written to `config_dir/alice-config.toml`, which should
/// be outside the sandbox (e.g., job_dir.base). The sandboxed process should
/// NOT have access to this file — it contains credential source references.
///
/// Credentials that use Keychain, OpenCode, or Inline sources cannot be
/// passed directly to alice (which only supports env/file sources). These
/// must be pre-resolved by the caller and their values will be referenced
/// via environment variables in the config.
///
/// Returns a `ProxyConfigResult` with the config path, env vars to set on
/// the alice process, and connection details.
#[allow(clippy::too_many_arguments)]
/// Reverse proxy configuration for alice to forward inbound traffic to a sandbox service.
#[derive(Debug, Clone)]
pub struct ReverseProxySetup {
    /// Address alice should listen on for inbound connections (e.g., "127.0.0.1:0")
    pub listen: String,
    /// Backend address inside the sandbox (e.g., "10.0.0.2:3337")
    pub backend: String,
}

#[allow(clippy::too_many_arguments)]
pub fn write_proxy_config(
    config_dir: &Path,
    ca_cert_path: &Path,
    listen_addr: &str,
    network_policy: Option<NetworkPolicy>,
    credentials: &[&Credential],
    proxy_username: Option<String>,
    proxy_password: Option<String>,
    otlp_endpoint: Option<String>,
    metrics_port: Option<u16>,
    reverse_proxy: Option<&ReverseProxySetup>,
) -> Result<ProxyConfigResult, String> {
    let mut env_vars: HashMap<String, String> = HashMap::new();
    let mut toml_parts: Vec<String> = Vec::new();

    // --- [proxy] section ---
    let port = listen_addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(crate::proxy_manager::DEFAULT_PROXY_PORT);

    let mut proxy_section = format!("[proxy]\nlisten = \"{}\"\n", listen_addr);

    if let Some(ref username) = proxy_username {
        proxy_section.push_str(&format!("username = \"{}\"\n", username));
        // Alice reads password from an env var, not inline
        let password_env = "ALICE_PROXY_PASSWORD";
        proxy_section.push_str(&format!("password_env = \"{}\"\n", password_env));
        if let Some(ref password) = proxy_password {
            let _ = env_vars.insert(password_env.to_string(), password.clone());
        }
    }

    toml_parts.push(proxy_section);

    // --- [ca] section ---
    toml_parts.push(format!(
        "[ca]\ncert_path = \"{}\"\n",
        ca_cert_path.display()
    ));

    // --- [[rules]] from network policy ---
    if let Some(ref policy) = network_policy {
        for rule in &policy.rules {
            let action = if rule.action == crate::jail::NetworkAction::Allow as i32 {
                "allow"
            } else {
                "deny"
            };

            if let Some(ref pattern) = rule.pattern {
                match &pattern.pattern {
                    Some(crate::jail::network_pattern::Pattern::Host(host_pattern)) => {
                        let mut rule_str = format!(
                            "[[rules]]\naction = \"{}\"\nhost = \"{}\"\n",
                            action, host_pattern.host
                        );
                        if let Some(ref path) = host_pattern.path {
                            rule_str.push_str(&format!("path = \"{}\"\n", path));
                        }
                        toml_parts.push(rule_str);
                    }
                    Some(crate::jail::network_pattern::Pattern::Ip(ip_pattern)) => {
                        toml_parts.push(format!(
                            "[[rules]]\naction = \"{}\"\ncidr = \"{}\"\n",
                            action, ip_pattern.cidr
                        ));
                    }
                    None => {}
                }
            }
        }
    }

    // --- [[credentials]] mapped from nix-jail credentials ---
    for (i, cred) in credentials.iter().enumerate() {
        // Determine the env var name for this credential's secret
        let env_var_name = format!("ALICE_CRED_{}", i);

        // Determine the alice credential source based on nix-jail's source type
        let source_line = match &cred.source {
            CredentialSource::Environment { source_env } => {
                // Direct passthrough — alice reads the same env var
                format!("env = \"{}\"", source_env)
            }
            CredentialSource::File { file_path } => {
                // Direct passthrough — alice reads the file
                format!("file = \"{}\"", file_path)
            }
            CredentialSource::Keychain { .. }
            | CredentialSource::OpenCodeAuth { .. }
            | CredentialSource::Inline { .. } => {
                // These must be pre-resolved by the orchestrator and passed via env var.
                // The env var value is NOT set here — the caller (ProxyManager) resolves
                // and injects it when spawning the alice process.
                format!("env = \"{}\"", env_var_name)
            }
        };

        // Parse header_format to extract alice's `header`, `match`, and `format` fields.
        //
        // nix-jail header_format specifies the full header line template:
        //   "Bearer {token}"     → header = "Authorization", format = "Bearer {value}"
        //   "x-api-key {token}"  → header = "x-api-key",     format = "{value}"
        //
        // For non-Authorization headers (like x-api-key), the header name is part of
        // header_format but must NOT appear in alice's match/format fields — alice
        // compares match_value against the header VALUE only, not "name value".
        let (header_name, alice_format, match_value) =
            if let Some(rest) = cred.header_format.strip_prefix("x-api-key ") {
                // Custom header: strip the header name prefix from format and match
                let fmt = rest.replace("{token}", "{value}");
                let mtch = if let Some(ref dummy) = cred.dummy_token {
                    rest.replace("{token}", dummy)
                } else {
                    String::new()
                };
                ("x-api-key", fmt, mtch)
            } else {
                // Authorization header: the entire format IS the header value
                let fmt = cred.header_format.replace("{token}", "{value}");
                let mtch = if let Some(ref dummy) = cred.dummy_token {
                    cred.header_format.replace("{token}", dummy)
                } else {
                    String::new()
                };
                ("Authorization", fmt, mtch)
            };

        // Generate one alice credential per host pattern
        for host_pattern in &cred.allowed_host_patterns {
            let mut cred_str = format!("[[credentials]]\nname = \"{}\"\n", cred.name);
            cred_str.push_str(&format!("host = \"{}\"\n", host_pattern));
            cred_str.push_str(&format!("header = \"{}\"\n", header_name));
            if !match_value.is_empty() {
                cred_str.push_str(&format!(
                    "match = \"{}\"\n",
                    match_value.replace('"', "\\\"")
                ));
            }
            cred_str.push_str(&format!("format = \"{}\"\n", alice_format));
            cred_str.push_str(&format!("{}\n", source_line));

            toml_parts.push(cred_str);
        }
    }

    // --- [observability] section ---
    if otlp_endpoint.is_some() || metrics_port.is_some() {
        let mut obs_section = "[observability]\n".to_string();
        if let Some(ref endpoint) = otlp_endpoint {
            obs_section.push_str(&format!("otlp_endpoint = \"{}\"\n", endpoint));
        }
        if let Some(port) = metrics_port {
            obs_section.push_str(&format!("metrics_listen = \"127.0.0.1:{}\"\n", port));
        }
        toml_parts.push(obs_section);
    }

    // --- [reverse_proxy] section ---
    if let Some(rp) = reverse_proxy {
        toml_parts.push(format!(
            "[reverse_proxy]\nlisten = \"{}\"\nbackend = \"{}\"\n",
            rp.listen, rp.backend
        ));
    }

    let toml_content = toml_parts.join("\n");
    let config_path = config_dir.join("alice-config.toml");
    std::fs::write(&config_path, &toml_content).map_err(|e| e.to_string())?;

    tracing::debug!("wrote alice proxy config to {}", config_path.display());

    Ok(ProxyConfigResult {
        config_path,
        env_vars,
        port,
        proxy_username,
        proxy_password,
        metrics_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialSource, CredentialType};
    use tempfile::TempDir;

    fn make_credential(name: &str, host: &str, source: CredentialSource) -> Credential {
        Credential {
            name: name.to_string(),
            credential_type: CredentialType::Generic,
            source,
            allowed_host_patterns: vec![host.to_string()],
            header_format: "Bearer {token}".to_string(),
            dummy_token: Some("DUMMY_TOKEN".to_string()),
            redact_response: true,
            redact_paths: vec![],
            extract_llm_metrics: false,
            llm_provider: None,
        }
    }

    #[test]
    fn test_write_proxy_config_empty() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_dir = temp_dir.path();
        let ca_cert_path = Path::new("/tmp/test-ca.pem");

        let empty_creds: Vec<&Credential> = vec![];
        let result = write_proxy_config(
            config_dir,
            ca_cert_path,
            "127.0.0.1:3128",
            None,
            &empty_creds,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("failed to write proxy config");

        assert!(result.config_path.exists());
        assert_eq!(result.config_path, config_dir.join("alice-config.toml"));
        assert_eq!(result.port, 3128);

        let content = std::fs::read_to_string(&result.config_path).expect("failed to read config");
        assert!(content.contains("[proxy]"));
        assert!(content.contains("listen = \"127.0.0.1:3128\""));
        assert!(content.contains("[ca]"));
        assert!(content.contains("cert_path = \"/tmp/test-ca.pem\""));
    }

    #[test]
    fn test_write_proxy_config_with_auth() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let empty_creds: Vec<&Credential> = vec![];

        let result = write_proxy_config(
            temp_dir.path(),
            Path::new("/tmp/ca.pem"),
            "0.0.0.0:3128",
            None,
            &empty_creds,
            Some("job-123".to_string()),
            Some("secret-password".to_string()),
            None,
            None,
            None,
        )
        .expect("failed to write proxy config");

        let content = std::fs::read_to_string(&result.config_path).expect("failed to read config");
        assert!(content.contains("username = \"job-123\""));
        assert!(content.contains("password_env = \"ALICE_PROXY_PASSWORD\""));
        assert_eq!(
            result.env_vars.get("ALICE_PROXY_PASSWORD"),
            Some(&"secret-password".to_string())
        );
    }

    #[test]
    fn test_write_proxy_config_with_credentials() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cred = make_credential(
            "github",
            "api.github.com",
            CredentialSource::Environment {
                source_env: "GITHUB_TOKEN".to_string(),
            },
        );
        let creds: Vec<&Credential> = vec![&cred];

        let result = write_proxy_config(
            temp_dir.path(),
            Path::new("/tmp/ca.pem"),
            "127.0.0.1:3128",
            None,
            &creds,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("failed to write proxy config");

        let content = std::fs::read_to_string(&result.config_path).expect("failed to read config");
        assert!(content.contains("[[credentials]]"));
        assert!(content.contains("name = \"github\""));
        assert!(content.contains("host = \"api.github.com\""));
        assert!(content.contains("header = \"Authorization\""));
        assert!(content.contains("match = \"Bearer DUMMY_TOKEN\""));
        assert!(content.contains("format = \"Bearer {value}\""));
        assert!(content.contains("env = \"GITHUB_TOKEN\""));
    }

    #[test]
    fn test_write_proxy_config_with_network_rules() {
        use crate::jail::{
            network_pattern::Pattern, HostPattern, NetworkAction, NetworkPattern, NetworkRule,
        };

        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let empty_creds: Vec<&Credential> = vec![];

        let policy = NetworkPolicy {
            rules: vec![
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(Pattern::Host(HostPattern {
                            host: "api.github.com".to_string(),
                            path: Some("/v1/*".to_string()),
                        })),
                    }),
                    action: NetworkAction::Allow as i32,
                    credential: Some("github".to_string()),
                },
                NetworkRule {
                    pattern: Some(NetworkPattern {
                        pattern: Some(Pattern::Host(HostPattern {
                            host: "*.evil.com".to_string(),
                            path: None,
                        })),
                    }),
                    action: NetworkAction::Deny as i32,
                    credential: None,
                },
            ],
        };

        let result = write_proxy_config(
            temp_dir.path(),
            Path::new("/tmp/ca.pem"),
            "127.0.0.1:3128",
            Some(policy),
            &empty_creds,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("failed to write proxy config");

        let content = std::fs::read_to_string(&result.config_path).expect("failed to read config");
        assert!(content.contains("action = \"allow\""));
        assert!(content.contains("host = \"api.github.com\""));
        assert!(content.contains("path = \"/v1/*\""));
        assert!(content.contains("action = \"deny\""));
        assert!(content.contains("host = \"*.evil.com\""));
    }

    #[test]
    fn test_keychain_credential_uses_env_var() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let cred = make_credential(
            "anthropic",
            "api.anthropic.com",
            CredentialSource::Keychain {
                keychain_service: "nix-jail-anthropic".to_string(),
                keychain_account: None,
            },
        );
        let creds: Vec<&Credential> = vec![&cred];

        let result = write_proxy_config(
            temp_dir.path(),
            Path::new("/tmp/ca.pem"),
            "127.0.0.1:3128",
            None,
            &creds,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("failed to write proxy config");

        let content = std::fs::read_to_string(&result.config_path).expect("failed to read config");
        // Keychain source should map to an env var reference
        assert!(content.contains("env = \"ALICE_CRED_0\""));
    }

    #[test]
    fn test_x_api_key_header_detection() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let mut cred = make_credential(
            "anthropic",
            "api.anthropic.com",
            CredentialSource::Environment {
                source_env: "ANTHROPIC_KEY".to_string(),
            },
        );
        cred.header_format = "x-api-key {token}".to_string();
        cred.dummy_token = Some("sk-dummy".to_string());
        let creds: Vec<&Credential> = vec![&cred];

        let result = write_proxy_config(
            temp_dir.path(),
            Path::new("/tmp/ca.pem"),
            "127.0.0.1:3128",
            None,
            &creds,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("failed to write proxy config");

        let content = std::fs::read_to_string(&result.config_path).expect("failed to read config");
        assert!(content.contains("header = \"x-api-key\""));
        assert!(content.contains("match = \"sk-dummy\""));
        assert!(content.contains("format = \"{value}\""));
    }
}
