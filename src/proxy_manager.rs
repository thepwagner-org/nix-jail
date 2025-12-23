//! Manages proxy lifecycle for individual jobs
//!
//! Each job gets its own proxy instance on a unique port.
//! The proxy is automatically terminated when dropped.
//!
//! # Path conventions
//!
//! The proxy writes its CA certificate to the job's root directory on the host.
//! Inside the sandbox (chroot), this becomes a different path:
//!
//! - **Host path**: `{root_dir}/etc/ssl/certs/ca-certificates.crt`
//! - **Chroot path**: `/etc/ssl/certs/ca-certificates.crt` (inside sandbox)
//!
//! Environment variables like `SSL_CERT_FILE` must use the chroot path.

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

/// Default proxy port (standard HTTP proxy port)
pub const DEFAULT_PROXY_PORT: u16 = 3128;

/// CA certificate path inside the sandbox (chroot-relative)
///
/// Use this for environment variables like SSL_CERT_FILE that are
/// interpreted inside the sandbox.
pub const CA_CERT_CHROOT_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

/// CA certificate path relative to root_dir (host-relative)
///
/// Use this to construct the host filesystem path where the cert is written.
/// The full host path is `{root_dir}/{CA_CERT_HOST_SUBPATH}`.
pub const CA_CERT_HOST_SUBPATH: &str = "etc/ssl/certs/ca-certificates.crt";

/// Manages a proxy instance for a single job
#[derive(Debug)]
pub struct ProxyManager {
    /// Proxy process handle
    proxy_process: Option<Child>,

    /// Port the proxy is listening on
    pub port: u16,

    /// Host/IP the proxy is listening on (platform-specific)
    pub listen_host: String,

    /// Job ID this proxy belongs to
    job_id: String,

    /// Optional username for HTTP Basic Auth
    proxy_username: Option<String>,

    /// Optional password for HTTP Basic Auth
    proxy_password: Option<String>,

    /// Stdout channel for streaming proxy logs
    pub stdout: Option<mpsc::Receiver<String>>,

    /// Stderr channel for streaming proxy logs
    pub stderr: Option<mpsc::Receiver<String>>,
}

impl ProxyManager {
    /// Compute the CA certificate host path from a root directory
    pub fn ca_cert_host_path(root_dir: &Path) -> PathBuf {
        root_dir.join(CA_CERT_HOST_SUBPATH)
    }

    /// Start a new proxy instance for a job
    ///
    /// The proxy will listen on a unique port and write its CA certificate
    /// to the job's root directory (accessible inside the sandbox).
    ///
    /// # Arguments
    /// * `job_id` - Unique identifier for this job
    /// * `root_dir` - Path to the job's root directory (becomes / inside sandbox)
    /// * `proxy_config_path` - Path to proxy configuration file
    /// * `listen_host` - Host/IP to bind to (e.g., "127.0.0.1" for macOS, "10.0.0.1" for Linux)
    pub async fn start(
        job_id: String,
        root_dir: PathBuf,
        proxy_config_path: PathBuf,
        listen_host: String,
    ) -> Result<Self, std::io::Error> {
        // CA cert host path - the proxy writes here, sandbox sees it at CA_CERT_CHROOT_PATH
        let ca_cert_host_path = Self::ca_cert_host_path(&root_dir);
        if let Some(cert_dir) = ca_cert_host_path.parent() {
            std::fs::create_dir_all(cert_dir)?;
        }

        // Read proxy config to get port and credentials
        let (port, proxy_username, proxy_password) = {
            use crate::proxy::ProxyConfig;
            match ProxyConfig::from_file(&proxy_config_path) {
                Ok(config) => {
                    // Extract port from listen_addr (e.g., "0.0.0.0:3128" -> 3128)
                    let port = config
                        .listen_addr
                        .rsplit(':')
                        .next()
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(DEFAULT_PROXY_PORT);
                    (port, config.proxy_username, config.proxy_password)
                }
                Err(e) => {
                    tracing::warn!(job_id = %job_id, "failed to read proxy config: {}", e);
                    (DEFAULT_PROXY_PORT, None, None)
                }
            }
        };

        tracing::debug!(job_id = %job_id, port = port, "Starting proxy for job");

        let current_exe = std::env::current_exe()?;
        let proxy_bin = current_exe
            .parent()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No parent dir"))?
            .join("nixjail-proxy");

        let (stdout_tx, stdout_rx) = mpsc::channel::<String>(128);
        let (stderr_tx, stderr_rx) = mpsc::channel::<String>(128);

        let mut proxy_cmd = Command::new(&proxy_bin);
        let _ = proxy_cmd.arg("--config").arg(&proxy_config_path);
        tracing::debug!(
            job_id = %job_id,
            config_path = %proxy_config_path.display(),
            "Proxy will use config file"
        );

        let mut proxy_process = proxy_cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true) // Important: kill proxy when this handle is dropped
            .spawn()?;

        let proxy_stdout = proxy_process
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("Failed to capture proxy stdout"))?;
        let proxy_stderr = proxy_process
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("Failed to capture proxy stderr"))?;

        // Spawn stdout streaming task (runs until receiver is dropped)
        drop(tokio::spawn(async move {
            let reader = BufReader::new(proxy_stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if stdout_tx.send(line).await.is_err() {
                    break; // Receiver dropped
                }
            }
        }));

        // Spawn stderr streaming task (runs until receiver is dropped)
        drop(tokio::spawn(async move {
            let reader = BufReader::new(proxy_stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if stderr_tx.send(line).await.is_err() {
                    break; // Receiver dropped
                }
            }
        }));

        tracing::debug!(job_id = %job_id, port = port, "Proxy started, waiting for CA cert");

        let mut attempts = 0;
        while !ca_cert_host_path.exists() && attempts < 500 {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            attempts += 1;

            if let Ok(Some(status)) = proxy_process.try_wait() {
                return Err(std::io::Error::other(format!(
                    "Proxy exited unexpectedly with status: {}",
                    status
                )));
            }
        }

        if !ca_cert_host_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Proxy did not write CA cert after 5 seconds",
            ));
        }

        tracing::info!(job_id = %job_id, ca_cert = %ca_cert_host_path.display(), "Proxy ready");

        Ok(Self {
            proxy_process: Some(proxy_process),
            port,
            listen_host,
            job_id,
            proxy_username,
            proxy_password,
            stdout: Some(stdout_rx),
            stderr: Some(stderr_rx),
        })
    }

    /// Get proxy URL for environment variables using the listen host
    ///
    /// Returns URL with embedded credentials if proxy authentication is enabled:
    /// - With auth: `http://job-123:password@127.0.0.1:3128`
    /// - Without auth: `http://127.0.0.1:3128`
    pub fn proxy_url(&self) -> String {
        self.proxy_url_with_host(&self.listen_host)
    }

    /// Get proxy URL with a specific host (for platform-specific connect addresses)
    ///
    /// Use this to build proxy URLs with the correct connect address:
    /// - Linux jobs connect via veth at 10.0.0.1
    /// - macOS jobs connect via localhost at 127.0.0.1
    pub fn proxy_url_with_host(&self, host: &str) -> String {
        match (&self.proxy_username, &self.proxy_password) {
            (Some(user), Some(pass)) => {
                format!("http://{}:{}@{}:{}", user, pass, host, self.port)
            }
            _ => {
                format!("http://{}:{}", host, self.port)
            }
        }
    }

    /// Take ownership of stdout channel for streaming
    pub fn take_stdout(&mut self) -> Option<mpsc::Receiver<String>> {
        self.stdout.take()
    }

    /// Take ownership of stderr channel for streaming
    pub fn take_stderr(&mut self) -> Option<mpsc::Receiver<String>> {
        self.stderr.take()
    }

    /// Stop the proxy (called automatically on drop)
    pub async fn stop(&mut self) {
        if let Some(mut process) = self.proxy_process.take() {
            tracing::info!(job_id = %self.job_id, "Stopping proxy");

            if let Some(pid) = process.id() {
                let pid = Pid::from_raw(pid as i32);
                if let Err(e) = signal::kill(pid, Signal::SIGTERM) {
                    tracing::warn!(job_id = %self.job_id, "Failed to send SIGTERM to proxy: {}", e);
                } else {
                    tracing::debug!(job_id = %self.job_id, "Sent SIGTERM to proxy, waiting for graceful shutdown");

                    // Wait up to 2 seconds for graceful shutdown
                    match tokio::time::timeout(Duration::from_secs(2), process.wait()).await {
                        Ok(Ok(status)) => {
                            tracing::info!(job_id = %self.job_id, "Proxy exited gracefully with status: {}", status);
                            return;
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(job_id = %self.job_id, "Error waiting for proxy: {}", e);
                        }
                        Err(_) => {
                            tracing::warn!(job_id = %self.job_id, "Proxy did not exit after SIGTERM, sending SIGKILL");
                        }
                    }
                }
            }

            let _ = process.kill().await;
            let _ = process.wait().await;
        }
    }
}

impl Drop for ProxyManager {
    fn drop(&mut self) {
        if let Some(mut process) = self.proxy_process.take() {
            if let Some(pid) = process.id() {
                let pid = Pid::from_raw(pid as i32);
                if signal::kill(pid, Signal::SIGTERM).is_ok() {
                    tracing::debug!(job_id = %self.job_id, "Sent SIGTERM to proxy on drop");
                    // Can't await in Drop, but process will get signal
                    return;
                }
            }

            let _ = process.start_kill();
            tracing::debug!(job_id = %self.job_id, "Proxy process killed on drop");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::write_proxy_config;
    use std::fs;

    #[tokio::test]
    async fn test_proxy_manager_lifecycle() {
        // Check if proxy binary exists (it needs to be built first: cargo build --bin proxy)
        let current_exe = std::env::current_exe().expect("failed to get current exe path");
        let proxy_bin = current_exe
            .parent()
            .expect("failed to get exe parent dir")
            .join("nixjail-proxy");

        if !proxy_bin.exists() {
            // Skip test if proxy binary isn't built
            tracing::warn!(
                proxy_bin = ?proxy_bin,
                "skipping test_proxy_manager_lifecycle: proxy binary not found, run 'cargo build --bin proxy' to build it"
            );
            return;
        }

        // Create temp directories for job
        let job_base = std::env::temp_dir().join(format!("test-proxy-{}", ulid::Ulid::new()));
        let root_dir = job_base.join("root");
        fs::create_dir_all(&root_dir).expect("Failed to create root dir");

        // Write proxy config to job base (outside sandbox)
        let ca_cert_host_path = ProxyManager::ca_cert_host_path(&root_dir);
        let empty_creds: Vec<&crate::config::Credential> = vec![];
        let config_path = write_proxy_config(
            &job_base,
            &ca_cert_host_path,
            &format!("127.0.0.1:{}", DEFAULT_PROXY_PORT),
            None,
            &empty_creds,
            None,
            None,
        )
        .expect("Failed to write proxy config");

        {
            // Start proxy
            let manager = ProxyManager::start(
                "test-job".to_string(),
                root_dir.clone(),
                config_path,
                "127.0.0.1".to_string(),
            )
            .await
            .expect("Failed to start proxy");

            // Verify CA cert was created in root dir (use helper to compute expected path)
            let expected_cert_path = ProxyManager::ca_cert_host_path(&root_dir);
            assert!(expected_cert_path.exists());
            assert!(expected_cert_path.starts_with(&root_dir));

            // Verify proxy URL
            assert!(manager.proxy_url().starts_with("http://127.0.0.1:"));

            // Proxy should be running
            assert!(manager.proxy_process.is_some());
        } // Proxy dropped here - should be killed

        // Cleanup
        let _ = fs::remove_dir_all(&job_base);
    }
}
