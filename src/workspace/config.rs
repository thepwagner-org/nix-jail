use std::fs;
use std::path::Path;

use super::WorkspaceError;
use crate::config::{Credential, CredentialSource, CredentialType};

/// Copy Claude Code configuration to workspace and create security wrapper or dummy files
///
/// Handles both keychain-based and file-based Claude credentials:
/// - Keychain: Creates security wrapper that returns dummy tokens (macOS)
/// - File: Creates dummy .claude.json and ~/.claude/.credentials.json files
///
/// The proxy will intercept requests and inject the real tokens.
pub fn setup_claude_config(
    job_base: &Path,
    workspace_home: &Path,
    job_id: &str,
    credentials: &[&Credential],
) -> Result<(), WorkspaceError> {
    use std::env;
    use std::path::Path;

    // Get user home directory, using SUDO_USER when running under sudo
    let user_home = if let Ok(sudo_user) = env::var("SUDO_USER") {
        format!("/home/{}", sudo_user)
    } else {
        env::var("HOME").map_err(|_| WorkspaceError::InvalidPath("HOME not set".to_string()))?
    };
    let user_home_path = Path::new(&user_home);

    // Find Claude credentials and determine their source type
    let claude_creds: Vec<&Credential> = credentials
        .iter()
        .filter(|c| c.credential_type == CredentialType::Claude)
        .copied()
        .collect();

    if claude_creds.is_empty() {
        tracing::debug!("no claude credentials found, skipping claude config setup");
        return Ok(());
    }

    // TEMPORARY: Copy entire ~/.claude/ directory for verification
    // TODO: Remove this and restore minimal config once we identify which files are needed
    let claude_dir = workspace_home.join(".claude");
    let source_claude_dir = user_home_path.join(".claude");
    if source_claude_dir.exists() {
        copy_dir_recursive(&source_claude_dir, &claude_dir)?;
        tracing::info!("TEMPORARY: copied entire ~/.claude/ to workspace for verification");
    } else {
        fs::create_dir_all(&claude_dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Make writable so Claude Code can modify files
        fs::set_permissions(&claude_dir, fs::Permissions::from_mode(0o777))?;
    }

    // Detect credential source type (keychain vs file)
    let has_keychain = claude_creds
        .iter()
        .any(|c| matches!(c.source, CredentialSource::Keychain { .. }));
    let has_file = claude_creds
        .iter()
        .any(|c| matches!(c.source, CredentialSource::File { .. }));

    // Copy essential config from ~/.claude.json to skip onboarding prompts
    // We need: oauthAccount (for auth), numStartups (skip first-run), theme (skip theme prompt)
    let claude_json = user_home_path.join(".claude.json");
    let dest_json = workspace_home.join(".claude.json");

    if claude_json.exists() {
        // Parse existing config and extract essential sections
        match fs::read_to_string(&claude_json) {
            Ok(json_content) => {
                match serde_json::from_str::<serde_json::Value>(&json_content) {
                    Ok(full_config) => {
                        // Extract sections needed to skip onboarding
                        let minimal_config = serde_json::json!({
                            "oauthAccount": full_config.get("oauthAccount"),
                            // Non-zero numStartups skips first-run prompts
                            "numStartups": full_config.get("numStartups").unwrap_or(&serde_json::json!(100)),
                            // Set theme to skip theme selection prompt
                            "theme": full_config.get("theme").unwrap_or(&serde_json::json!("dark")),
                        });

                        // Write minimal config
                        let minimal_json =
                            serde_json::to_string_pretty(&minimal_config).map_err(|e| {
                                WorkspaceError::IoError(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("Failed to serialize minimal config: {}", e),
                                ))
                            })?;
                        fs::write(&dest_json, &minimal_json)?;
                        tracing::debug!("copied essential config from .claude.json to workspace");
                    }
                    Err(e) => {
                        tracing::warn!("failed to parse .claude.json: {}, skipping", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("failed to read .claude.json: {}, skipping", e);
            }
        }
    } else {
        // No existing config - create minimal one to skip onboarding
        let minimal_config = serde_json::json!({
            "numStartups": 100,
            "theme": "dark",
        });
        let minimal_json = serde_json::to_string_pretty(&minimal_config).unwrap_or_default();
        if let Err(e) = fs::write(&dest_json, minimal_json) {
            tracing::warn!("failed to write .claude.json: {}", e);
        }
    }

    // Handle file-based credentials: create dummy .claude.json and ~/.claude/.credentials.json
    if has_file {
        for cred in &claude_creds {
            if let CredentialSource::File { file_path } = &cred.source {
                setup_file_based_credential(workspace_home, job_id, file_path)?;
            }
        }
    }

    // Handle keychain-based credentials: create security wrapper
    if !has_keychain {
        tracing::debug!(job_id = %job_id, "no keychain-based claude credentials, skipping security wrapper");
        return Ok(());
    }

    // Create security wrapper that returns a fixed dummy token
    // The dummy token is defined in the credential config file (dummy_token field)
    // The proxy intercepts requests and replaces the dummy with the real token
    let bin_dir = job_base.join("bin");
    fs::create_dir_all(&bin_dir)?;

    let security_wrapper = bin_dir.join("security");

    // Fixed dummy token - must match dummy_token in credential config
    const DUMMY_ACCESS_TOKEN: &str = "sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_AAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAA";
    const DUMMY_REFRESH_TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA_AAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-AAAA";

    // Fetch real token JSON structure but replace tokens with dummies
    let dummy_token_json = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            "Claude Code-credentials",
            "-w",
        ])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                let token_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let mut json_value: serde_json::Value = serde_json::from_str(&token_str).ok()?;

                // Replace tokens with fixed dummies
                if let Some(claude_oauth) = json_value.get_mut("claudeAiOauth") {
                    claude_oauth["accessToken"] =
                        serde_json::Value::String(DUMMY_ACCESS_TOKEN.to_string());
                    claude_oauth["refreshToken"] =
                        serde_json::Value::String(DUMMY_REFRESH_TOKEN.to_string());
                }

                let dummy_json = serde_json::to_string(&json_value).ok()?;
                tracing::info!(job_id = %job_id, "created dummy token json for security wrapper");
                Some(dummy_json)
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            tracing::warn!(job_id = %job_id, "failed to fetch claude oauth token from keychain, using minimal dummy");
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"{}","refreshToken":"{}"}}}}"#,
                DUMMY_ACCESS_TOKEN, DUMMY_REFRESH_TOKEN
            )
        });

    let wrapper_script = format!(
        r#"#!/bin/bash
# Security wrapper that returns dummy OAuth token JSON
# The proxy will detect the dummy accessToken and inject the real one
# This keeps keychain access out of the sandbox and real tokens never enter

# Debug logging - remove after debugging
exec 3>>/tmp/nix-jail-security.log
echo "[$(date)] security wrapper called: $@" >&3
echo "[$(date)] PATH=$PATH" >&3
echo "[$(date)] PWD=$PWD" >&3

DUMMY_TOKEN_JSON='{}'

# Check if this is a find-generic-password command
if [[ "$1" == "find-generic-password" ]]; then
    # Parse arguments to extract service name
    service_name=""
    has_w_flag=false

    args=("$@")
    for i in "${{!args[@]}}"; do
        if [[ "${{args[$i]}}" == "-s" ]] && [[ -n "${{args[$i+1]}}" ]]; then
            service_name="${{args[$i+1]}}"
        fi
        if [[ "${{args[$i]}}" == "-w" ]]; then
            has_w_flag=true
        fi
    done

    # Check if this is requesting Claude Code credentials
    echo "[$(date)] service_name='$service_name' has_w_flag=$has_w_flag" >&3
    if [[ "$service_name" =~ ^Claude\ Code(-credentials)?(-[a-f0-9]{{8}})?$ ]]; then
        echo "[$(date)] MATCH - returning dummy token" >&3
        if [[ "$has_w_flag" == "true" ]]; then
            # Just output the dummy token JSON
            echo "[$(date)] output: $DUMMY_TOKEN_JSON" >&3
            echo "$DUMMY_TOKEN_JSON"
        else
            # Output in keychain format
            echo "password: \"$DUMMY_TOKEN_JSON\""
        fi
        exit 0
    else
        echo "[$(date)] NO MATCH - service_name doesn't match regex" >&3
        echo "security: The specified item could not be found in the keychain." >&2
        exit 44
    fi
else
    # Other security commands not supported
    echo "security: Operation not supported in sandbox" >&2
    exit 1
fi
"#,
        dummy_token_json
    );

    fs::write(&security_wrapper, wrapper_script)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&security_wrapper, fs::Permissions::from_mode(0o755))?;
    }

    tracing::info!(job_id = %job_id, wrapper_path = %security_wrapper.display(), "created security wrapper with dummy token");

    Ok(())
}

/// Setup file-based Claude credential by creating dummy credential files
///
/// Reads the real credential from the specified file path, creates dummy versions,
/// and writes both .claude.json and ~/.claude/.credentials.json to the workspace.
fn setup_file_based_credential(
    workspace_home: &Path,
    job_id: &str,
    file_path: &str,
) -> Result<(), WorkspaceError> {
    use std::env;
    use std::path::Path;

    // Expand ~ to home directory
    // When running under sudo, use SUDO_USER to get the real user's home directory
    let expanded_path = if file_path.starts_with("~/") {
        let home = if let Ok(sudo_user) = env::var("SUDO_USER") {
            format!("/home/{}", sudo_user)
        } else {
            env::var("HOME").map_err(|_| WorkspaceError::InvalidPath("HOME not set".to_string()))?
        };
        file_path.replacen("~", &home, 1)
    } else {
        file_path.to_string()
    };

    let credential_path = Path::new(&expanded_path);

    // Read the real credential file
    let real_credential_json = fs::read_to_string(credential_path).map_err(|e| {
        WorkspaceError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Failed to read credential file {}: {}", expanded_path, e),
        ))
    })?;

    // Parse and create dummy version
    let mut json_value: serde_json::Value =
        serde_json::from_str(&real_credential_json).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse credential JSON: {}", e),
            ))
        })?;

    // Helper function to create dummy token
    let make_dummy = |real_token: &str, prefix: &str| -> String {
        let mut dummy = prefix.to_string();
        for ch in real_token[prefix.len()..].chars() {
            if ch.is_alphanumeric() {
                dummy.push('A');
            } else {
                dummy.push(ch); // Keep special chars like - and _
            }
        }
        dummy
    };

    // Replace .claudeAiOauth.accessToken with dummy
    if let Some(claude_oauth) = json_value.get_mut("claudeAiOauth") {
        if let Some(access_token) = claude_oauth.get("accessToken").and_then(|v| v.as_str()) {
            let dummy_access = if access_token.starts_with("sk-ant-oat01-") {
                make_dummy(access_token, "sk-ant-oat01-")
            } else {
                "dummy-access-token".to_string()
            };
            claude_oauth["accessToken"] = serde_json::Value::String(dummy_access);
        }

        // Replace .claudeAiOauth.refreshToken with dummy
        if let Some(refresh_token) = claude_oauth.get("refreshToken").and_then(|v| v.as_str()) {
            let dummy_refresh = make_dummy(refresh_token, "");
            claude_oauth["refreshToken"] = serde_json::Value::String(dummy_refresh);
        }
    }

    let dummy_json = serde_json::to_string_pretty(&json_value).map_err(|e| {
        WorkspaceError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to serialize dummy credential: {}", e),
        ))
    })?;

    // Write dummy .claude/.credentials.json to workspace
    // (.claude directory already created in setup_claude_config with correct permissions)
    let claude_dir = workspace_home.join(".claude");
    let credentials_json = claude_dir.join(".credentials.json");
    fs::write(&credentials_json, &dummy_json)?;

    tracing::info!(
        job_id = %job_id,
        path = %credentials_json.display(),
        "created dummy ~/.claude/.credentials.json for file-based credential"
    );

    // Note: .claude.json is already created by setup_claude_config() with the trimmed
    // oauthAccount section from the user's ~/.claude.json file

    Ok(())
}

/// TEMPORARY: Recursively copy a directory
/// TODO: Remove this once we identify which specific files are needed
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), WorkspaceError> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            // Skip certain directories that shouldn't be copied
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == "todos"
                || name_str == "statsig"
                || name_str == "debug"
                || name_str == "projects"
            {
                continue;
            }
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if src_path.is_symlink() {
            // Follow symlinks and copy the target file
            if let Ok(target) = fs::read_link(&src_path) {
                let resolved = if target.is_absolute() {
                    target
                } else {
                    src_path.parent().unwrap_or(src).join(&target)
                };
                if resolved.exists() && resolved.is_file() {
                    fs::copy(&resolved, &dst_path)?;
                }
            }
        } else {
            // Skip large files like conversation logs
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".jsonl") {
                continue;
            }
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}
