use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

pub use crate::root::StoreStrategy;

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    /// Base directory for all persistent state (database, cache, etc.)
    pub state_dir: PathBuf,
    pub db_path: PathBuf,
    /// Credentials that can be exposed to jobs
    pub credentials: Vec<Credential>,
    /// Strategy for setting up Nix store in sandbox
    pub store_strategy: StoreStrategy,
    /// OpenTelemetry OTLP endpoint for distributed tracing (e.g., "http://localhost:4317")
    pub otlp_endpoint: Option<String>,
}

/// Type of credential for determining setup requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    /// Claude Code credentials (requires .claude.json setup)
    Claude,
    /// GitHub credentials
    GitHub,
    /// Generic HTTP credential
    Generic,
}

/// A credential that can be injected into network requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Name to reference this credential (e.g., "anthropic", "github")
    pub name: String,

    /// Type of credential (determines setup requirements)
    #[serde(rename = "type")]
    pub credential_type: CredentialType,

    /// Where to fetch the credential from
    #[serde(flatten)]
    pub source: CredentialSource,

    /// Host patterns this credential is allowed for (regex)
    pub allowed_host_patterns: Vec<String>,

    /// Header format template (e.g., "Bearer {token}", "token {token}")
    pub header_format: String,

    /// Expected dummy token value to replace (optional)
    /// If set, the proxy will only inject if it finds this exact dummy token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dummy_token: Option<String>,
}

/// Source of a credential value
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialSource {
    /// Fetch from macOS Keychain
    Keychain {
        keychain_service: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        keychain_account: Option<String>,
    },
    /// Fetch from environment variable
    Environment { source_env: String },
    /// Fetch from file (e.g., ~/.claude/.credentials.json)
    File { file_path: String },
}

impl Default for ServerConfig {
    fn default() -> Self {
        let state_dir = PathBuf::from("/var/lib/nix-jail");
        Self {
            // Safety: hardcoded address is guaranteed valid
            #[allow(clippy::expect_used)]
            addr: "127.0.0.1:50051".parse().expect("valid socket address"),
            state_dir: state_dir.clone(),
            db_path: state_dir.join("nix-jail.db"),
            credentials: Vec::new(),
            store_strategy: StoreStrategy::default(),
            otlp_endpoint: None,
        }
    }
}

impl Credential {
    /// Find a credential by name
    pub fn find_by_name<'a>(credentials: &'a [Credential], name: &str) -> Option<&'a Credential> {
        credentials.iter().find(|c| c.name == name)
    }
}

/// Fetch token from a credential source (async wrapper for blocking operations)
pub async fn fetch_credential_token(credential: &Credential) -> Result<String, String> {
    let source = credential.source.clone();

    // Run blocking credential fetch in a separate thread
    tokio::task::spawn_blocking(move || fetch_credential_token_sync(&source))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

/// Fetch token from a credential source (synchronous implementation)
fn fetch_credential_token_sync(source: &CredentialSource) -> Result<String, String> {
    match source {
        CredentialSource::Keychain {
            keychain_service,
            keychain_account,
        } => fetch_from_keychain(keychain_service, keychain_account.as_deref()),
        CredentialSource::Environment { source_env } => std::env::var(source_env)
            .map_err(|e| format!("Environment variable {} not found: {}", source_env, e)),
        CredentialSource::File { file_path } => fetch_from_file(file_path),
    }
}

/// Fetch token from macOS Keychain
fn fetch_from_keychain(service: &str, account: Option<&str>) -> Result<String, String> {
    let mut cmd = std::process::Command::new("/usr/bin/security");
    let _ = cmd.args(["find-generic-password", "-s", service, "-w"]);

    if let Some(acc) = account {
        let _ = cmd.args(["-a", acc]);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to run security command: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Keychain lookup failed (service={}): {}",
            service,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let raw_output = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if raw_output.is_empty() {
        return Err(format!("Empty token from keychain (service={})", service));
    }

    // For Claude Code credentials, the keychain stores JSON: {"claudeAiOauth":{"accessToken":"sk-ant-oat01-..."}}
    // Extract just the accessToken value
    if service.starts_with("Claude Code") {
        if let Some(start) = raw_output.find("sk-ant-oat01-") {
            let token_part = &raw_output[start..];
            let token_end = token_part.find('"').unwrap_or(token_part.len());
            let token = &token_part[..token_end];
            Ok(token.to_string())
        } else {
            Err("Failed to extract accessToken from Claude Code keychain entry".to_string())
        }
    } else {
        // For other services, return the raw value
        Ok(raw_output)
    }
}

/// Fetch token from file (e.g., ~/.claude/.credentials.json)
fn fetch_from_file(file_path: &str) -> Result<String, String> {
    // Expand ~ to home directory
    // When running under sudo, use SUDO_USER to get the real user's home directory
    let expanded_path = if file_path.starts_with("~/") {
        let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            format!("/home/{}", sudo_user)
        } else {
            std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?
        };
        file_path.replacen("~", &home, 1)
    } else {
        file_path.to_string()
    };

    // Security: Validate path to prevent traversal attacks
    let path = PathBuf::from(&expanded_path);
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(format!(
                "Path traversal not allowed in credential file path: {}",
                file_path
            ));
        }
    }

    // Read the file
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read credential file {}: {}", expanded_path, e))?;

    // Parse JSON and extract accessToken
    // Expected format: {"claudeAiOauth":{"accessToken":"sk-ant-oat01-..."}}
    if let Some(start) = contents.find("sk-ant-oat01-") {
        let token_part = &contents[start..];
        let token_end = token_part.find('"').unwrap_or(token_part.len());
        let token = &token_part[..token_end];
        Ok(token.to_string())
    } else {
        Err(format!(
            "Failed to extract accessToken from credential file {}",
            expanded_path
        ))
    }
}

/// TOML file structure for server configuration
#[derive(Debug, Deserialize)]
struct ServerConfigFile {
    #[serde(default)]
    server: ServerSection,
    #[serde(default)]
    credentials: Vec<Credential>,
}

#[derive(Debug, Deserialize)]
struct ServerSection {
    #[serde(default = "default_addr")]
    addr: String,
    #[serde(default = "default_state_dir")]
    state_dir: String,
    #[serde(default = "default_db_path")]
    db_path: String,
    #[serde(default = "default_store_strategy")]
    store_strategy: String,
    /// OpenTelemetry OTLP endpoint (e.g., "http://localhost:4317")
    otlp_endpoint: Option<String>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            addr: default_addr(),
            state_dir: default_state_dir(),
            db_path: default_db_path(),
            store_strategy: default_store_strategy(),
            otlp_endpoint: None,
        }
    }
}

fn default_addr() -> String {
    "127.0.0.1:50051".to_string()
}

fn default_state_dir() -> String {
    "/var/lib/nix-jail".to_string()
}

fn default_db_path() -> String {
    "nix-jail.db".to_string()
}

fn default_store_strategy() -> String {
    "cached".to_string()
}

impl ServerConfig {
    /// Load server configuration from TOML file
    pub fn from_toml_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: ServerConfigFile = toml::from_str(&contents)?;

        let state_dir = PathBuf::from(&config.server.state_dir);

        // Resolve db_path relative to state_dir if not absolute
        let db_path = {
            let p = PathBuf::from(&config.server.db_path);
            if p.is_absolute() {
                p
            } else {
                state_dir.join(p)
            }
        };

        let store_strategy: StoreStrategy = config
            .server
            .store_strategy
            .parse()
            .map_err(|e: String| e)?;

        Ok(Self {
            addr: config.server.addr.parse()?,
            state_dir,
            db_path,
            credentials: config.credentials,
            store_strategy,
            otlp_endpoint: config.server.otlp_endpoint,
        })
    }

    /// Find a credential by name
    pub fn find_credential(&self, name: &str) -> Option<&Credential> {
        Credential::find_by_name(&self.credentials, name)
    }

    /// Get the cache directory path
    pub fn cache_dir(&self) -> PathBuf {
        self.state_dir.join("cache")
    }
}

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_url: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:50051".to_string(),
        }
    }
}

/// Runtime constants
pub const CHANNEL_BUFFER_SIZE: usize = 128;
