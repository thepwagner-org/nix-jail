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
///
/// When `insecure_credentials` is true, real credentials are passed directly to the
/// sandbox instead of dummy tokens. This is for debugging credential issues only.
pub fn setup_claude_config(
    job_base: &Path,
    workspace_home: &Path,
    job_id: &str,
    credentials: &[&Credential],
    insecure_credentials: bool,
) -> Result<(), WorkspaceError> {
    use std::env;
    use std::path::Path;

    tracing::debug!(
        job_id = %job_id,
        job_base = %job_base.display(),
        workspace_home = %workspace_home.display(),
        num_credentials = credentials.len(),
        insecure = insecure_credentials,
        "setup_claude_config called"
    );

    // Get user home directory, using SUDO_USER when running under sudo
    let user_home = if let Ok(sudo_user) = env::var("SUDO_USER") {
        tracing::debug!(sudo_user = %sudo_user, "running under sudo");
        // macOS uses /Users, Linux uses /home
        if cfg!(target_os = "macos") {
            format!("/Users/{}", sudo_user)
        } else {
            format!("/home/{}", sudo_user)
        }
    } else {
        tracing::debug!("not running under sudo, using HOME");
        env::var("HOME").map_err(|_| WorkspaceError::InvalidPath("HOME not set".to_string()))?
    };
    tracing::debug!(user_home = %user_home, "resolved user home directory");
    let user_home_path = Path::new(&user_home);

    // Find Claude credentials and determine their source type
    let claude_creds: Vec<&Credential> = credentials
        .iter()
        .filter(|c| c.credential_type == CredentialType::Claude)
        .copied()
        .collect();

    tracing::debug!(
        job_id = %job_id,
        claude_cred_count = claude_creds.len(),
        cred_types = ?claude_creds.iter().map(|c| format!("{:?}", c.source)).collect::<Vec<_>>(),
        "found claude credentials"
    );

    if claude_creds.is_empty() {
        tracing::debug!("no claude credentials found, skipping claude config setup");
        return Ok(());
    }

    // TEMPORARY: Copy entire ~/.claude/ directory for verification
    // TODO: Remove this and restore minimal config once we identify which files are needed
    let claude_dir = workspace_home.join(".claude");
    let source_claude_dir = user_home_path.join(".claude");
    tracing::debug!(
        source = %source_claude_dir.display(),
        dest = %claude_dir.display(),
        source_exists = source_claude_dir.exists(),
        "checking source .claude directory"
    );
    if source_claude_dir.exists() {
        copy_dir_recursive(&source_claude_dir, &claude_dir)?;
        tracing::info!(
            source = %source_claude_dir.display(),
            dest = %claude_dir.display(),
            "copied entire ~/.claude/ to workspace"
        );
    } else {
        tracing::warn!(
            source = %source_claude_dir.display(),
            "source .claude directory does not exist, creating empty"
        );
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

    // Copy entire ~/.claude.json to workspace
    let claude_json = user_home_path.join(".claude.json");
    let dest_json = workspace_home.join(".claude.json");

    if claude_json.exists() {
        match fs::copy(&claude_json, &dest_json) {
            Ok(_) => {
                tracing::debug!(
                    source = %claude_json.display(),
                    dest = %dest_json.display(),
                    "copied .claude.json to workspace"
                );
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
                setup_file_based_credential(
                    workspace_home,
                    job_id,
                    file_path,
                    insecure_credentials,
                )?;
            }
        }
    }

    // Handle keychain-based credentials: create security wrapper
    if !has_keychain {
        tracing::debug!(job_id = %job_id, "no keychain-based claude credentials, skipping security wrapper");
        return Ok(());
    }

    // Find the keychain credential to get the dummy_token from config
    let keychain_cred = claude_creds
        .iter()
        .find(|c| matches!(c.source, CredentialSource::Keychain { .. }));

    let dummy_access_token = keychain_cred
        .and_then(|c| c.dummy_token.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("DUMMY_TOKEN_NOT_CONFIGURED");

    // Create security wrapper that returns a fixed dummy token
    // The dummy token is defined in the credential config file (dummy_token field)
    // The proxy intercepts requests and replaces the dummy with the real token
    let bin_dir = job_base.join("bin");
    fs::create_dir_all(&bin_dir)?;

    let security_wrapper = bin_dir.join("security");

    // Dummy refresh token - uses same pattern as access token but without sk-ant-oat01- prefix
    let dummy_refresh_token = if dummy_access_token.starts_with("sk-ant-oat01-") {
        dummy_access_token
            .strip_prefix("sk-ant-oat01-")
            .unwrap_or(dummy_access_token)
    } else {
        dummy_access_token
    };

    // Fetch real token JSON from keychain
    // When insecure_credentials is true, use real tokens directly (DANGEROUS - for debugging only)
    // When false (normal mode), replace with dummy tokens for proxy injection
    let token_json = std::process::Command::new("/usr/bin/security")
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

                if insecure_credentials {
                    // INSECURE MODE: Return real token JSON directly
                    tracing::warn!(
                        job_id = %job_id,
                        "INSECURE: using real keychain tokens in security wrapper"
                    );
                    Some(token_str)
                } else {
                    // SECURE MODE: Replace tokens with dummies
                    let mut json_value: serde_json::Value =
                        serde_json::from_str(&token_str).ok()?;
                    if let Some(claude_oauth) = json_value.get_mut("claudeAiOauth") {
                        claude_oauth["accessToken"] =
                            serde_json::Value::String(dummy_access_token.to_string());
                        claude_oauth["refreshToken"] =
                            serde_json::Value::String(dummy_refresh_token.to_string());
                    }

                    let dummy_json = serde_json::to_string(&json_value).ok()?;
                    tracing::info!(job_id = %job_id, "created dummy token json for security wrapper");
                    Some(dummy_json)
                }
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            tracing::warn!(job_id = %job_id, "failed to fetch claude oauth token from keychain, using minimal dummy");
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"{}","refreshToken":"{}"}}}}"#,
                dummy_access_token, dummy_refresh_token
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
        token_json
    );

    fs::write(&security_wrapper, wrapper_script)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&security_wrapper, fs::Permissions::from_mode(0o755))?;
    }

    if insecure_credentials {
        tracing::warn!(job_id = %job_id, wrapper_path = %security_wrapper.display(), "created INSECURE security wrapper with REAL tokens");
    } else {
        tracing::info!(job_id = %job_id, wrapper_path = %security_wrapper.display(), "created security wrapper with dummy token");
    }

    Ok(())
}

/// Setup file-based Claude credential by creating credential files
///
/// Reads the real credential from the specified file path, creates dummy versions
/// (or uses real credentials when insecure_credentials is true), and writes to
/// ~/.claude/.credentials.json in the workspace.
fn setup_file_based_credential(
    workspace_home: &Path,
    job_id: &str,
    file_path: &str,
    insecure_credentials: bool,
) -> Result<(), WorkspaceError> {
    use std::env;
    use std::path::Path;

    // Expand ~ to home directory
    // When running under sudo, use SUDO_USER to get the real user's home directory
    let expanded_path = if file_path.starts_with("~/") {
        let home = if let Ok(sudo_user) = env::var("SUDO_USER") {
            // macOS uses /Users, Linux uses /home
            if cfg!(target_os = "macos") {
                format!("/Users/{}", sudo_user)
            } else {
                format!("/home/{}", sudo_user)
            }
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

    // INSECURE MODE: Use real credentials directly
    let output_json = if insecure_credentials {
        tracing::warn!(
            job_id = %job_id,
            "INSECURE: using real file-based credentials in workspace"
        );
        real_credential_json
    } else {
        // SECURE MODE: Parse and create dummy version
        let mut json_value: serde_json::Value = serde_json::from_str(&real_credential_json)
            .map_err(|e| {
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

        serde_json::to_string_pretty(&json_value).map_err(|e| {
            WorkspaceError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to serialize dummy credential: {}", e),
            ))
        })?
    };

    // Write credential JSON to workspace
    // (.claude directory already created in setup_claude_config with correct permissions)
    let claude_dir = workspace_home.join(".claude");
    let credentials_json = claude_dir.join(".credentials.json");
    fs::write(&credentials_json, &output_json)?;

    if insecure_credentials {
        tracing::warn!(
            job_id = %job_id,
            path = %credentials_json.display(),
            "created INSECURE ~/.claude/.credentials.json with REAL tokens"
        );
    } else {
        tracing::info!(
            job_id = %job_id,
            path = %credentials_json.display(),
            "created dummy ~/.claude/.credentials.json for file-based credential"
        );
    }

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
