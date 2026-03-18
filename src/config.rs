use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
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
    /// Path to existing monorepo clone for sparse checkout support
    /// If set, uses this as the source for workspace clones instead of fetching fresh
    pub monorepo_path: Option<PathBuf>,
    /// Cargo/build cache configuration
    pub cache: CacheConfig,
    /// Port for Prometheus metrics HTTP endpoint (optional)
    /// When set, exposes /metrics on this port
    pub metrics_port: Option<u16>,
    /// Bind address for metrics HTTP endpoint (optional)
    /// Defaults to the same IP as the main server address
    pub metrics_bind_address: Option<IpAddr>,
    /// Default environment variables for all jobs
    /// These are set before job-specific env vars (server wins on conflicts)
    pub default_env: Vec<(String, String)>,
    /// Explicit path to alice proxy binary (overrides PATH lookup)
    /// Set by NixOS module to the nix store path of the alice package
    pub proxy_binary: Option<PathBuf>,
    /// Directory containing job profile TOML files (e.g., `profiles/opencode.toml`).
    /// When set, `JobRequest::profile` is resolved from this directory.
    /// Defaults to `{state_dir}/profiles` when not set.
    pub profile_dir: Option<PathBuf>,
    /// Named shell environments available to job profiles.
    /// Each entry maps a shell name (e.g. `"sandbox"`) to a nix store path that
    /// provides a set of tools.  Profiles reference shells by name via the `shell`
    /// field; the resolved store path is appended to the job's package list.
    pub shells: std::collections::HashMap<String, PathBuf>,
    /// Domain used for generating git author emails in the sandbox.
    /// When set and `git` is in the job closure, a `~/.gitconfig` is written with
    /// `user.name = nix-jail[project]` and `user.email = nix-jail+project@<domain>`.
    pub git_email_domain: Option<String>,
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
    /// Also accepts `type = "opencode"` for backwards compatibility (same behaviour)
    #[serde(alias = "opencode")]
    Generic,
}

/// LLM provider type for API response parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LlmProvider {
    /// Anthropic API (Claude)
    #[default]
    Anthropic,
    /// OpenAI API (GPT models)
    OpenAI,
}

/// Default for redact_response - true for security by default
fn default_redact_response() -> bool {
    true
}

/// Default OAuth paths to redact - only actual token refresh endpoints
fn default_redact_paths() -> Vec<String> {
    vec![r"/oauth/token".to_string(), r"/token$".to_string()]
}

/// Default for extract_llm_metrics - true to capture usage stats
fn default_extract_llm_metrics() -> bool {
    true
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

    /// Host glob patterns this credential is allowed for (e.g., "api.github.com", "*.example.com")
    pub allowed_host_patterns: Vec<String>,

    /// Header format template (e.g., "Bearer {token}", "token {token}")
    pub header_format: String,

    /// Expected dummy token value to replace (optional)
    /// If set, the proxy will only inject if it finds this exact dummy token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dummy_token: Option<String>,

    /// Redact OAuth tokens from responses for this credential
    /// When true, responses matching redact_paths will have tokens replaced with dummies
    /// Defaults to true for security - set to false to disable
    #[serde(default = "default_redact_response")]
    pub redact_response: bool,

    /// Path patterns that trigger response redaction (e.g., ["/oauth/token", "/token"])
    /// Defaults to common OAuth paths - override to customize
    #[serde(default = "default_redact_paths")]
    pub redact_paths: Vec<String>,

    /// Enable LLM API metrics extraction for this credential
    /// When true, parses request/response bodies to extract token usage and tool calls
    /// Defaults to true - set to false to disable
    #[serde(default = "default_extract_llm_metrics")]
    pub extract_llm_metrics: bool,

    /// LLM provider type for response parsing
    /// Auto-detected from host patterns if not specified
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_provider: Option<LlmProvider>,
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
    /// Fetch from OpenCode's auth.json file
    /// Reads ~/.local/share/opencode/auth.json and extracts token for the specified provider
    OpenCodeAuth {
        /// Provider ID in auth.json (e.g., "anthropic", "openai")
        opencode_provider_id: String,
    },
    /// Inline token (for ephemeral credentials)
    /// SECURITY: Never serialized - serde(skip) prevents persistence
    #[serde(skip)]
    Inline { token: String },
}

/// Configuration for caching
///
/// The server accepts any bucket name from clients (validated alphanumeric)
/// and creates cache directories dynamically under {state_dir}/cache/{bucket}/
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CacheConfig {
    /// Enable caching (default: true)
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
}

fn default_cache_enabled() -> bool {
    true
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
            monorepo_path: None,
            cache: CacheConfig::default(),
            metrics_port: None,
            metrics_bind_address: None,
            default_env: Vec::new(),
            proxy_binary: None,
            profile_dir: None,
            shells: std::collections::HashMap::new(),
            git_email_domain: None,
        }
    }
}

impl Credential {
    /// Find a credential by name
    pub fn find_by_name<'a>(credentials: &'a [Credential], name: &str) -> Option<&'a Credential> {
        credentials.iter().find(|c| c.name == name)
    }
}

impl From<&crate::jail::EphemeralCredential> for Credential {
    fn from(ec: &crate::jail::EphemeralCredential) -> Self {
        Credential {
            name: ec.name.clone(),
            credential_type: CredentialType::Generic,
            source: CredentialSource::Inline {
                token: ec.token.clone(),
            },
            allowed_host_patterns: ec.allowed_hosts.clone(),
            header_format: ec.header_format.clone(),
            dummy_token: None,
            redact_response: default_redact_response(),
            redact_paths: default_redact_paths(),
            extract_llm_metrics: false,
            llm_provider: None,
        }
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
        CredentialSource::Inline { token } => Ok(token.clone()),
        CredentialSource::Keychain {
            keychain_service,
            keychain_account,
        } => fetch_from_keychain(keychain_service, keychain_account.as_deref()),
        CredentialSource::Environment { source_env } => std::env::var(source_env)
            .map_err(|e| format!("Environment variable {} not found: {}", source_env, e)),
        CredentialSource::File { file_path } => fetch_from_file(file_path),
        CredentialSource::OpenCodeAuth {
            opencode_provider_id,
        } => fetch_from_opencode_auth(opencode_provider_id),
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

    // For Claude Code credentials, return the full JSON
    // The proxy handles extracting accessToken when needed for Authorization header
    // and uses the full JSON for x-api-key header
    Ok(raw_output)
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

    // Read the file and return raw contents
    // For Claude credentials, this is the full JSON that the proxy will use
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read credential file {}: {}", expanded_path, e))?;

    Ok(contents.trim().to_string())
}

/// Extract accessToken from Claude credential JSON
/// The raw JSON format is: {"claudeAiOauth":{"accessToken":"sk-ant-oat01-...",...}}
pub fn extract_access_token(raw_json: &str) -> Option<String> {
    // Find the accessToken value - look for sk-ant-oat01- prefix
    if let Some(start) = raw_json.find("sk-ant-oat01-") {
        let token_part = &raw_json[start..];
        let token_end = token_part.find('"').unwrap_or(token_part.len());
        Some(token_part[..token_end].to_string())
    } else {
        None
    }
}

/// Fetch token from OpenCode's auth.json file
///
/// OpenCode stores credentials in ~/.local/share/opencode/auth.json with the format:
/// ```json
/// {
///   "anthropic": { "type": "oauth", "access": "sk-ant-...", "refresh": "...", "expires": 123 },
///   "openai": { "type": "api", "key": "sk-..." }
/// }
/// ```
fn fetch_from_opencode_auth(provider_id: &str) -> Result<String, String> {
    // Resolve home directory (handle SUDO_USER for daemon running as root)
    let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        // Check /Users first (macOS), then /home (Linux)
        let macos_home = format!("/Users/{}", sudo_user);
        if std::path::Path::new(&macos_home).exists() {
            macos_home
        } else {
            format!("/home/{}", sudo_user)
        }
    } else {
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?
    };

    let auth_path = PathBuf::from(&home).join(".local/share/opencode/auth.json");

    let contents = std::fs::read_to_string(&auth_path).map_err(|e| {
        format!(
            "Failed to read OpenCode auth.json at {}: {}",
            auth_path.display(),
            e
        )
    })?;

    let auth_data: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| format!("Failed to parse OpenCode auth.json: {}", e))?;

    let provider = auth_data
        .get(provider_id)
        .ok_or_else(|| format!("Provider '{}' not found in OpenCode auth.json", provider_id))?;

    let auth_type = provider
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing 'type' field for provider '{}'", provider_id))?;

    match auth_type {
        "oauth" => {
            // OAuth credentials have an "access" field with the access token
            provider
                .get("access")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    format!(
                        "Missing 'access' field for OAuth provider '{}'",
                        provider_id
                    )
                })
        }
        "api" => {
            // API credentials have a "key" field
            provider
                .get("key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| format!("Missing 'key' field for API provider '{}'", provider_id))
        }
        "wellknown" => {
            // Well-known credentials have a "token" field
            provider
                .get("token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    format!(
                        "Missing 'token' field for wellknown provider '{}'",
                        provider_id
                    )
                })
        }
        _ => Err(format!(
            "Unknown auth type '{}' for provider '{}'",
            auth_type, provider_id
        )),
    }
}

/// TOML file structure for server configuration
#[derive(Debug, Deserialize)]
struct ServerConfigFile {
    #[serde(default)]
    server: ServerSection,
    #[serde(default)]
    credentials: Vec<Credential>,
    #[serde(default)]
    cache: CacheConfig,
    /// Named shell environments: maps shell name to nix store path.
    /// Referenced by profiles via `shell = "name"`.
    #[serde(default)]
    shells: std::collections::HashMap<String, String>,
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
    /// Path to existing monorepo clone for sparse checkout support
    monorepo_path: Option<String>,
    /// Port for Prometheus metrics HTTP endpoint
    metrics_port: Option<u16>,
    /// Bind address for metrics HTTP endpoint (e.g., "0.0.0.0" for external access)
    metrics_bind_address: Option<String>,
    /// Default environment variables for all jobs
    /// Format: [["KEY1", "VALUE1"], ["KEY2", "VALUE2"]]
    #[serde(default)]
    default_env: Vec<[String; 2]>,
    /// Explicit path to alice proxy binary
    proxy_binary: Option<String>,
    /// Directory containing job profile TOML files.
    profile_dir: Option<String>,
    /// Domain for git author emails in sandboxes (e.g. "example.com").
    git_email_domain: Option<String>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            addr: default_addr(),
            state_dir: default_state_dir(),
            db_path: default_db_path(),
            store_strategy: default_store_strategy(),
            otlp_endpoint: None,
            monorepo_path: None,
            metrics_port: None,
            metrics_bind_address: None,
            default_env: Vec::new(),
            proxy_binary: None,
            profile_dir: None,
            git_email_domain: None,
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

        // Convert [[key, value], ...] to Vec<(String, String)>
        let default_env: Vec<(String, String)> = config
            .server
            .default_env
            .into_iter()
            .map(|[k, v]| (k, v))
            .collect();

        let metrics_bind_address = config
            .server
            .metrics_bind_address
            .map(|s| s.parse())
            .transpose()?;

        Ok(Self {
            addr: config.server.addr.parse()?,
            state_dir,
            db_path,
            credentials: config.credentials,
            store_strategy,
            otlp_endpoint: config.server.otlp_endpoint,
            monorepo_path: config.server.monorepo_path.map(PathBuf::from),
            cache: config.cache,
            metrics_port: config.server.metrics_port,
            metrics_bind_address,
            default_env,
            proxy_binary: config.server.proxy_binary.map(PathBuf::from),
            profile_dir: config.server.profile_dir.map(PathBuf::from),
            shells: config
                .shells
                .into_iter()
                .map(|(k, v)| (k, PathBuf::from(v)))
                .collect(),
            git_email_domain: config.server.git_email_domain,
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

    /// Get the profile directory, defaulting to `{state_dir}/profiles`.
    pub fn profile_dir(&self) -> PathBuf {
        self.profile_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("profiles"))
    }

    /// Load a profile by name from the profile directory.
    pub fn load_profile(&self, name: &str) -> Result<Profile, String> {
        Profile::load_by_name(&self.profile_dir(), name)
    }
}

/// Job profile loaded from a TOML file.
///
/// A profile bundles the common settings for a particular kind of job
/// (e.g., "opencode") so they don't need to be spelled out on every invocation.
/// Profiles are stored in `{profile_dir}/{name}.toml` on the server.
///
/// When a `JobRequest` references a profile by name the server merges the profile
/// with the request.  **Explicit request fields always win over profile defaults.**
///
/// The `credentials` list references credential names that must already exist in
/// the server config (`server.toml`).  Credentials are never embedded in profile
/// files to keep secrets out of version-controlled config.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    /// Human-readable label (optional).
    pub description: Option<String>,

    /// Hardening profile to use for systemd execution.
    /// One of `"default"` or `"jit-runtime"`.  Defaults to `"default"`.
    #[serde(default)]
    pub hardening: Option<String>,

    /// The script to run inside the sandbox.  Mutually exclusive with
    /// `script_file` (which is not yet implemented).
    pub script: Option<String>,

    /// Port the job's web service listens on inside the sandbox.
    /// Sets `JobRequest::service_port` when not provided by the caller.
    pub service_port: Option<u32>,

    /// Environment variables injected into the sandbox.
    #[serde(default)]
    pub environment: std::collections::HashMap<String, String>,

    /// Names of server-configured credentials to make available to this job.
    /// Credentials must already exist in `server.toml`; the profile only
    /// references them by name so secrets stay out of profile files.
    #[serde(default)]
    pub credentials: Vec<String>,

    /// Network policy rules for the job.
    #[serde(default)]
    pub network: ProfileNetwork,

    /// Nix packages to make available (in addition to any flake devShell).
    #[serde(default)]
    pub packages: Vec<String>,

    /// Named shell environment to use for this profile.
    /// The name must match an entry in the server config `[shells]` table.
    /// The resolved store path is appended to the job's package list (additive
    /// with any explicit `packages`).
    pub shell: Option<String>,
}

/// Network rules section of a profile.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProfileNetwork {
    /// Ordered list of rules (first match wins).
    #[serde(default)]
    pub rules: Vec<crate::networkpolicy::ClientNetworkRule>,
}

impl Profile {
    /// Load a profile from a TOML file.
    pub fn from_toml_file(path: &std::path::Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read profile {}: {}", path.display(), e))?;
        toml::from_str(&contents)
            .map_err(|e| format!("failed to parse profile {}: {}", path.display(), e))
    }

    /// Load a profile by name from the given directory.
    ///
    /// The file is expected at `{dir}/{name}.toml`.
    pub fn load_by_name(dir: &std::path::Path, name: &str) -> Result<Self, String> {
        // Reject names that could escape the directory.
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(format!("invalid profile name: {name:?}"));
        }
        let path = dir.join(format!("{name}.toml"));
        Self::from_toml_file(&path)
    }

    /// Apply this profile as defaults to the given `JobRequest`.
    ///
    /// Fields already set in `req` (non-empty strings, non-None optionals, etc.)
    /// are left unchanged.  Profile values fill in the blanks.
    pub fn apply_defaults_to(
        &self,
        req: &mut crate::jail::JobRequest,
        server_credentials: &[Credential],
        shells: &std::collections::HashMap<String, PathBuf>,
    ) {
        // Script: use profile script only if the request has none.
        if req.script.is_empty() {
            if let Some(ref s) = self.script {
                req.script = s.clone();
            }
        }

        // Hardening profile.
        if req.hardening_profile.is_none() {
            if let Some(ref h) = self.hardening {
                req.hardening_profile = Some(h.clone());
            }
        }

        // Service port.
        if req.service_port.is_none() {
            if let Some(p) = self.service_port {
                req.service_port = Some(p);
            }
        }

        // Packages: extend rather than replace.
        for pkg in &self.packages {
            if !req.packages.contains(pkg) {
                req.packages.push(pkg.clone());
            }
        }

        // Shell: resolve the named shell to a store path and add it to packages.
        if let Some(ref shell_name) = self.shell {
            match shells.get(shell_name) {
                Some(path) => {
                    let path_str = path.to_string_lossy().into_owned();
                    if !req.packages.contains(&path_str) {
                        req.packages.push(path_str);
                    }
                }
                None => {
                    tracing::warn!(
                        shell = %shell_name,
                        "profile references unknown shell (not in server config)"
                    );
                }
            }
        }

        // Environment variables: profile vars are the base; request vars win.
        for (k, v) in &self.environment {
            let _ = req.env.entry(k.clone()).or_insert_with(|| v.clone());
        }

        // Network policy: extend the existing policy with this profile's rules.
        // Additive so multiple profiles can each contribute network rules that
        // accumulate in application order (first-match-wins within the rules list).
        if !self.network.rules.is_empty() {
            let new_proto = crate::networkpolicy::ClientNetworkPolicy {
                rules: self.network.rules.clone(),
            }
            .to_proto();
            match req.network_policy {
                Some(ref mut policy) => policy.rules.extend(new_proto.rules),
                None => req.network_policy = Some(new_proto),
            }
        }

        // Credentials: store matched credentials so the orchestrator can look them up.
        // We inject them as ephemeral credentials if they exist in server config.
        // (Nothing extra is needed here because the service layer resolves named
        // credentials from server config against the network policy at orchestration time.)
        let _ = server_credentials; // reserved for future use
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_fetch_from_opencode_auth_oauth() {
        // Create a temporary auth.json file
        let mut file = NamedTempFile::new().unwrap();
        let auth_json = r#"{
            "anthropic": {
                "type": "oauth",
                "access": "sk-ant-test-token-12345",
                "refresh": "refresh-token",
                "expires": 1234567890
            }
        }"#;
        file.write_all(auth_json.as_bytes()).unwrap();

        // We can't easily test fetch_from_opencode_auth directly since it
        // uses hardcoded paths. Instead, test the JSON parsing logic.
        let auth_data: serde_json::Value = serde_json::from_str(auth_json).unwrap();
        let provider = auth_data.get("anthropic").unwrap();
        let auth_type = provider.get("type").and_then(|v| v.as_str()).unwrap();
        assert_eq!(auth_type, "oauth");
        let access = provider.get("access").and_then(|v| v.as_str()).unwrap();
        assert_eq!(access, "sk-ant-test-token-12345");
    }

    #[test]
    fn test_fetch_from_opencode_auth_api() {
        let auth_json = r#"{
            "openai": {
                "type": "api",
                "key": "sk-openai-test-key"
            }
        }"#;
        let auth_data: serde_json::Value = serde_json::from_str(auth_json).unwrap();
        let provider = auth_data.get("openai").unwrap();
        let auth_type = provider.get("type").and_then(|v| v.as_str()).unwrap();
        assert_eq!(auth_type, "api");
        let key = provider.get("key").and_then(|v| v.as_str()).unwrap();
        assert_eq!(key, "sk-openai-test-key");
    }

    #[test]
    fn test_default_env_toml_parsing() {
        let toml_content = r#"
[server]
addr = "127.0.0.1:50051"
state_dir = "/tmp/test-nix-jail"
default_env = [
    ["OPENCODE_DISABLE_LSP_DOWNLOAD", "true"],
    ["ANTHROPIC_API_KEY", "dummy-key"],
]

[cache]
enabled = true
"#;
        let config: ServerConfigFile = toml::from_str(toml_content).unwrap();
        assert_eq!(config.server.default_env.len(), 2);
        assert_eq!(
            config.server.default_env[0],
            ["OPENCODE_DISABLE_LSP_DOWNLOAD", "true"]
        );
        assert_eq!(
            config.server.default_env[1],
            ["ANTHROPIC_API_KEY", "dummy-key"]
        );
    }

    #[test]
    fn test_credential_source_opencode_auth_deserialize() {
        let toml_content = r#"
name = "anthropic-opencode"
type = "opencode"
opencode_provider_id = "anthropic"
allowed_host_patterns = ["api.anthropic.com"]
header_format = "x-api-key {token}"
"#;
        let cred: Credential = toml::from_str(toml_content).unwrap();
        assert_eq!(cred.name, "anthropic-opencode");
        // "opencode" is an alias for "generic" - the type only controls sandbox setup
        // behaviour, which is the same for both. The actual token source is driven by
        // the CredentialSource variant (OpenCodeAuth), not the type.
        assert_eq!(cred.credential_type, CredentialType::Generic);
        assert!(
            matches!(
                cred.source,
                CredentialSource::OpenCodeAuth { opencode_provider_id } if opencode_provider_id == "anthropic"
            ),
            "Expected OpenCodeAuth source with anthropic provider"
        );
    }
}
