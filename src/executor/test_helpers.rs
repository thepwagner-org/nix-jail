//! Shared test utilities for executor tests
//!
//! Provides builders and helpers to reduce boilerplate in executor unit tests.

use super::traits::{ExecutionConfig, ExecutionHandle, HardeningProfile, IoHandle};
use crate::root::StoreSetup;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Builder for ExecutionConfig with sensible test defaults
///
/// All fields default to values that work for most unit tests:
/// - `working_dir` and `root_dir` default to `/tmp`
/// - `timeout` defaults to 10 seconds
/// - `store_setup` defaults to `Populated`
/// - `interactive` defaults to false
pub struct TestConfigBuilder {
    job_id: String,
    command: Vec<String>,
    env: HashMap<String, String>,
    working_dir: PathBuf,
    root_dir: PathBuf,
    store_setup: StoreSetup,
    timeout: Duration,
    store_paths: Vec<PathBuf>,
    proxy_port: Option<u16>,
    hardening_profile: HardeningProfile,
    interactive: bool,
    pty_size: Option<(u16, u16)>,
}

#[allow(dead_code)]
impl TestConfigBuilder {
    /// Create a new builder with the given job ID
    pub fn new(job_id: &str) -> Self {
        Self {
            job_id: job_id.to_string(),
            command: vec![],
            env: HashMap::new(),
            working_dir: PathBuf::from("/tmp"),
            root_dir: PathBuf::from("/tmp"),
            store_setup: StoreSetup::Populated,
            timeout: Duration::from_secs(10),
            store_paths: vec![],
            proxy_port: None,
            hardening_profile: HardeningProfile::Default,
            interactive: false,
            pty_size: None,
        }
    }

    /// Set the command to execute
    pub fn command(mut self, cmd: Vec<&str>) -> Self {
        self.command = cmd.into_iter().map(String::from).collect();
        self
    }

    /// Add an environment variable
    pub fn env(mut self, key: &str, value: &str) -> Self {
        let _ = self.env.insert(key.to_string(), value.to_string());
        self
    }

    /// Set the working directory
    pub fn working_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.working_dir = path.into();
        self
    }

    /// Set the root directory
    pub fn root_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.root_dir = path.into();
        self
    }

    /// Set the execution timeout
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = duration;
        self
    }

    /// Set the store paths (nix closure)
    pub fn store_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.store_paths = paths;
        self
    }

    /// Set the proxy port (enables localhost network access in sandbox)
    pub fn proxy_port(mut self, port: u16) -> Self {
        self.proxy_port = Some(port);
        self
    }

    /// Build the ExecutionConfig
    pub fn build(self) -> ExecutionConfig {
        ExecutionConfig {
            job_id: self.job_id,
            command: self.command,
            env: self.env,
            working_dir: self.working_dir,
            root_dir: self.root_dir,
            store_setup: self.store_setup,
            timeout: self.timeout,
            store_paths: self.store_paths,
            proxy_port: self.proxy_port,
            hardening_profile: self.hardening_profile,
            interactive: self.interactive,
            pty_size: self.pty_size,
            cache_mounts: vec![], // No caching in tests by default
        }
    }
}

/// Collected output from a job execution
#[derive(Debug)]
pub struct ExecutionOutput {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub exit_code: i32,
}

/// Collect all output from an ExecutionHandle
///
/// Drains stdout and stderr channels and waits for the exit code.
/// Panics if the handle is in PTY mode (use `collect_pty_output` instead).
pub async fn collect_output(handle: ExecutionHandle) -> ExecutionOutput {
    match handle.io {
        IoHandle::Piped {
            mut stdout,
            mut stderr,
        } => {
            let mut stdout_lines = vec![];
            let mut stderr_lines = vec![];

            // Drain both channels
            loop {
                tokio::select! {
                    line = stdout.recv() => {
                        match line {
                            Some(l) => stdout_lines.push(l),
                            None => break,
                        }
                    }
                    line = stderr.recv() => {
                        if let Some(l) = line {
                            stderr_lines.push(l);
                        }
                    }
                }
            }

            // Drain remaining stderr
            while let Ok(line) = stderr.try_recv() {
                stderr_lines.push(line);
            }

            let exit_code = handle.exit_code.await.expect("failed to get exit code");

            ExecutionOutput {
                stdout: stdout_lines,
                stderr: stderr_lines,
                exit_code,
            }
        }
        IoHandle::Pty { .. } => {
            panic!("collect_output does not support PTY mode");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let config = TestConfigBuilder::new("test-job").build();

        assert_eq!(config.job_id, "test-job");
        assert!(config.command.is_empty());
        assert_eq!(config.working_dir, PathBuf::from("/tmp"));
        assert_eq!(config.root_dir, PathBuf::from("/tmp"));
        assert_eq!(config.timeout, Duration::from_secs(10));
        assert!(!config.interactive);
    }

    #[test]
    fn test_builder_with_command() {
        let config = TestConfigBuilder::new("test-job")
            .command(vec!["echo", "hello", "world"])
            .build();

        assert_eq!(
            config.command,
            vec!["echo".to_string(), "hello".to_string(), "world".to_string()]
        );
    }

    #[test]
    fn test_builder_with_env() {
        let config = TestConfigBuilder::new("test-job")
            .env("FOO", "bar")
            .env("BAZ", "qux")
            .build();

        assert_eq!(config.env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(config.env.get("BAZ"), Some(&"qux".to_string()));
    }
}
