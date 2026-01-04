//! Proxy configuration generation for jobs
//!
//! Creates proxy-config.json files that configure the MITM proxy with
//! network policies and credentials. The config file is stored outside
//! the sandbox (in job_dir.base) so the sandboxed process cannot access it.

use crate::config::Credential;
use crate::jail::NetworkPolicy;
use crate::proxy::ProxyConfig;
use std::path::{Path, PathBuf};

/// Generate a cryptographically random password for proxy authentication
pub fn generate_proxy_password() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

/// Write proxy configuration file to the job's base directory
///
/// The config file is written to `config_dir/proxy-config.json`, which should
/// be outside the sandbox (e.g., job_dir.base). The sandboxed process should
/// NOT have access to this file - it contains credential information.
///
/// Returns the path to the written config file.
pub fn write_proxy_config(
    config_dir: &Path,
    ca_cert_path: &Path,
    listen_addr: &str,
    network_policy: Option<NetworkPolicy>,
    credentials: &[&Credential],
    proxy_username: Option<String>,
    proxy_password: Option<String>,
) -> Result<PathBuf, String> {
    let config = ProxyConfig {
        listen_addr: listen_addr.to_string(),
        ca_cert_path: ca_cert_path.to_path_buf(),
        network_policy,
        credentials: credentials.iter().map(|c| (*c).clone()).collect(),
        proxy_username,
        proxy_password,
        request_log_path: None,
    };

    let config_path = config_dir.join("proxy-config.json");
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    std::fs::write(&config_path, &json).map_err(|e| e.to_string())?;

    tracing::debug!("wrote proxy config to {}", config_path.display());

    Ok(config_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_proxy_config() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let config_dir = temp_dir.path();
        let ca_cert_path = Path::new("/tmp/test-ca.pem");

        let empty_creds: Vec<&Credential> = vec![];
        let config_path = write_proxy_config(
            config_dir,
            ca_cert_path,
            "127.0.0.1:3128",
            None,
            &empty_creds,
            None,
            None,
        )
        .expect("failed to write proxy config");

        assert!(config_path.exists());
        assert_eq!(config_path, config_dir.join("proxy-config.json"));

        // Verify we can read it back
        let json = std::fs::read_to_string(&config_path).expect("failed to read config file");
        let config: ProxyConfig = serde_json::from_str(&json).expect("failed to parse config json");
        assert_eq!(config.listen_addr, "127.0.0.1:3128");
        assert_eq!(config.ca_cert_path, ca_cert_path);
        assert!(config.network_policy.is_none());
        assert_eq!(config.credentials.len(), 0);
    }
}
