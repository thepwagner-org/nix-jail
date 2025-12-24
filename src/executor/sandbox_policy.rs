//! macOS sandbox profile generation
//!
//! Provides Sandbox Profile Language (SBPL) generation for macOS sandbox-exec.
//! Profiles enforce least-privilege execution with explicit allow rules for:
//! - Nix store closure (read-only)
//! - Workspace directory (read-write)
//! - Localhost proxy access
//! - Essential system resources

use std::path::{Path, PathBuf};

/// Cache directories configuration for sandbox profile
#[derive(Debug, Default)]
pub struct CachePaths {
    /// CARGO_HOME directory (shared registry/git deps)
    pub cargo_home: Option<PathBuf>,
    /// CARGO_TARGET_DIR directory (per-repo build artifacts)
    pub target_dir: Option<PathBuf>,
    /// PNPM store directory (shared pnpm packages)
    pub pnpm_store: Option<PathBuf>,
}

/// Generate a Sandbox Profile Language (SBPL) profile for macOS sandbox-exec
///
/// Creates a profile that restricts filesystem access to:
/// - The Nix store paths in the derivation closure (read-only)
/// - The workspace directory (read-write)
/// - The job root directory (for CA cert access when using proxy)
/// - Cache directories for Cargo (read-write, if configured)
/// - Essential macOS system resources (metadata, sysctls)
/// - Network access only to the specified proxy port on localhost (if proxy_port is Some)
///
/// # Security
/// - Uses deny-by-default policy
/// - Explicitly silences expected denials to reduce log noise
/// - Grants minimal permissions required for Nix builds
/// - When proxy_port is None, network access is completely blocked
#[cfg_attr(not(test), allow(dead_code))]
pub fn generate_profile(
    closure_paths: &[PathBuf],
    workspace_path: &Path,
    root_dir: &Path,
    proxy_port: Option<u16>,
) -> String {
    generate_profile_with_cache(closure_paths, workspace_path, root_dir, proxy_port, None)
}

/// Generate sandbox profile with optional cache directories
pub fn generate_profile_with_cache(
    closure_paths: &[PathBuf],
    workspace_path: &Path,
    root_dir: &Path,
    proxy_port: Option<u16>,
    cache_paths: Option<&CachePaths>,
) -> String {
    let mut profile = String::from("(version 1)\n");
    profile.push_str("(deny default)\n\n");

    profile.push_str(";; Security: Deny-by-default with explicit allow rules\n\n");

    // Silence expected denial spam in kernel logs
    profile.push_str(";; Explicit denials with no-log to reduce kernel log spam\n");
    profile.push_str("(deny mach-lookup (with no-log) (global-name \"com.apple.diagnosticd\"))\n");
    profile.push_str("(deny mach-lookup (with no-log) (global-name \"com.apple.SystemConfiguration.configd\"))\n");
    profile.push_str("(deny mach-lookup (with no-log) (global-name \"com.apple.SystemConfiguration.DNSConfiguration\"))\n");
    profile.push_str(
        "(deny mach-lookup (with no-log) (global-name \"com.apple.system.notification_center\"))\n",
    );
    profile.push_str("(deny mach-lookup (with no-log) (global-name \"com.apple.logd\"))\n");
    profile.push_str("(deny file-write-data (with no-log) (literal \"/dev/dtracehelper\"))\n");
    profile.push_str("(deny network-outbound (with no-log) (remote ip \"*:443\"))\n");
    profile.push_str("(deny system-socket (with no-log))\n");
    profile.push_str("(deny file-read-data (with no-log) (literal \"/dev/autofs_nowait\"))\n");
    profile.push_str(
        "(deny file-read-data (with no-log) (regex #\"^/Users/[^/]+/\\\\.CFUserTextEncoding$\"))\n",
    );
    // profile.push_str("(deny file-read-metadata (with no-log) (regex #\"^/Users/\"))\n\n");

    // Allow reading from Nix store closure paths
    profile.push_str(";; Nix store closure (read-only)\n");
    for path in closure_paths {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            path.display()
        ));
    }
    profile.push('\n');

    // Allow execution of binaries in the closure
    profile.push_str(";; Allow process execution from closure\n");
    for path in closure_paths {
        profile.push_str(&format!(
            "(allow process-exec* (subpath \"{}\"))\n",
            path.display()
        ));
    }
    profile.push('\n');

    // Too much glue relies on shells
    profile.push_str("(allow file-read-metadata (literal \"/bin\"))\n");
    profile.push_str("(allow file-read-metadata (literal \"/run\"))\n");
    for shell in ["bash", "sh"] {
        profile.push_str(&format!(
            "(allow process-exec* (literal \"/bin/{}\"))\n",
            shell
        ));
        profile.push_str(&format!(
            "(allow file-read-metadata (literal \"/bin/{}\"))\n",
            shell
        ));
        profile.push_str(&format!(
            "(allow file-read-data (literal \"/bin/{}\"))\n",
            shell
        ));
        profile.push_str(&format!(
            "(allow file-read-metadata (literal \"/private/var/select/{}\"))\n",
            shell
        ));
    }

    profile.push_str("(allow file-read-metadata (literal \"/usr\"))\n");
    profile.push_str("(allow file-read-metadata (literal \"/usr/bin\"))\n");
    profile.push_str("(allow file-read-data (literal \"/usr/bin\"))\n");

    // xcrun for SDK lookup (needed by rustc linker)
    profile.push_str("(allow file-read* (literal \"/usr/bin/xcrun\"))\n");
    profile.push_str("(allow process-exec* (literal \"/usr/bin/xcrun\"))\n");
    profile.push_str("(allow file-read* (literal \"/private/var/db/xcode_select_link\"))\n");

    // No keychain access needed - security wrapper returns pre-fetched credentials
    profile.push('\n');

    // Allow workspace access (read-write and execute for build scripts)
    profile.push_str(";; Workspace access (read-write, execute for cargo build scripts)\n");
    profile.push_str(&format!(
        "(allow file-read* file-write* process-exec* (subpath \"{}\"))\n\n",
        workspace_path.display()
    ));

    // Allow wrapper bin directory (for security wrapper script)
    if let Some(job_base) = workspace_path.parent() {
        let wrapper_bin = job_base.join("bin");
        profile.push_str(";; Wrapper bin directory (security wrapper)\n");
        profile.push_str(&format!(
            "(allow file-read-metadata (subpath \"{}\"))\n",
            wrapper_bin.display()
        ));
        profile.push_str(&format!(
            "(allow file-read-data (subpath \"{}\"))\n",
            wrapper_bin.display()
        ));
        profile.push_str(&format!(
            "(allow process-exec* (subpath \"{}\"))\n\n",
            wrapper_bin.display()
        ));
    }

    // Allow reading CA cert from job root directory (for MITM proxy TLS)
    if proxy_port.is_some() {
        profile.push_str(";; Job root directory (CA cert for proxy TLS)\n");
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n\n",
            root_dir.display()
        ));
    }

    // Allow cache directory access (read-write for Cargo registry, read-write-exec for target)
    if let Some(cache) = cache_paths {
        if cache.cargo_home.is_some() || cache.target_dir.is_some() {
            profile.push_str(";; Cargo cache directories\n");
        }
        if let Some(cargo_home) = &cache.cargo_home {
            profile.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n",
                cargo_home.display()
            ));
        }
        if let Some(target_dir) = &cache.target_dir {
            // Target directory needs process-exec* for build scripts
            profile.push_str(&format!(
                "(allow file-read* file-write* process-exec* (subpath \"{}\"))\n",
                target_dir.display()
            ));
        }
        if cache.cargo_home.is_some() || cache.target_dir.is_some() {
            profile.push('\n');
        }
        if let Some(pnpm_store) = &cache.pnpm_store {
            profile.push_str(";; pnpm store directory\n");
            profile.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n\n",
                pnpm_store.display()
            ));
        }
    }

    // Essential macOS permissions
    profile.push_str(";; Essential macOS permissions\n");
    profile.push_str("(allow file-read-metadata\n");
    profile.push_str("  (literal \"/nix\")\n");
    profile.push_str("  (literal \"/private\")  ; Required for /tmp symlink resolution\n");
    profile.push_str("  (subpath \"/nix/store\")\n");
    profile.push_str("  (subpath \"/System/Library\")\n");
    profile.push_str("  (subpath \"/System/Cryptexes\")\n");
    profile.push_str("  (subpath \"/usr/lib\")\n");
    profile.push_str("  (subpath \"/usr/share\")\n");
    profile.push_str("  (subpath \"/Library/Apple\")\n");
    profile.push_str("  (subpath \"/Library/Preferences\")\n");
    profile.push_str("  (subpath \"/var\")\n");
    profile.push_str("  (subpath \"/etc\")\n");
    profile.push_str("  (subpath \"/tmp\")\n");
    profile.push_str("  (subpath \"/private/tmp\")\n");
    profile.push_str("  (literal \"/private/var/db/timezone/zoneinfo\")\n");
    profile.push_str("  (literal \"/\"))\n");
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow ipc-posix-shm)\n\n");

    // Specific mach services (instead of blanket mach-lookup)
    profile.push_str(";; Specific Mach services\n");
    profile.push_str("(allow mach-lookup (global-name \"com.apple.system.logger\"))\n");
    profile.push_str(
        "(allow mach-lookup (global-name \"com.apple.system.DirectoryService.libinfo_v1\"))\n",
    );
    profile.push_str(
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\"))\n\n",
    );

    // Allow minimal system resources needed for execution
    profile.push_str(";; System resources needed for execution\n");
    profile.push_str("(allow file-read-data (literal \"/\"))\n"); // Bash needs to read root dir
    profile.push_str("(allow file-read* file-write* (literal \"/dev/null\"))\n");
    profile.push_str("(allow file-read* file-write* (literal \"/dev/tty\"))\n");
    profile.push_str("(allow file-read* (literal \"/dev/random\"))\n");
    profile.push_str("(allow file-read* (literal \"/dev/urandom\"))\n");
    profile.push_str("(allow file-read* (literal \"/dev/dtracehelper\"))\n");
    profile.push_str("(allow file-read* (subpath \"/dev/fd\"))\n"); // Process substitution for Nix wrappers (read-only)
    profile.push_str("(allow file-read* (subpath \"/usr/lib\"))\n");
    profile.push_str("(allow file-read* (subpath \"/usr/share\"))\n"); // zoneinfo, locale
    profile.push_str("(allow file-read* (literal \"/private/etc/localtime\"))\n"); // Timezone info (node needs this)
    profile.push_str("(allow file-read* (subpath \"/System/Library\"))\n");
    profile.push_str("(allow file-read* (subpath \"/System/Volumes/Preboot/Cryptexes\"))\n");
    profile.push_str("(allow file-read* (subpath \"/Library/Apple\"))\n");
    profile.push_str("(allow file-read* (subpath \"/Library/Developer\"))\n"); // CommandLineTools SDK for xcrun
    profile.push_str("(allow file-read* (subpath \"/Library/Preferences\"))\n");

    // Network restrictions - localhost only (for MITM proxy)
    // Note: macOS sandbox profiles don't support port-specific restrictions
    if let Some(port) = proxy_port {
        profile.push_str(&format!(
            ";; Network access - localhost only (proxy on port {})\n",
            port
        ));
        profile.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
        profile.push_str("(allow network-outbound (remote unix-socket))\n");
    } else {
        profile.push_str(";; Network access - completely blocked (no proxy configured)\n");
        profile.push_str(";; All network-outbound operations will be denied by default\n");
    }

    // Allow binding to localhost for test servers (wiremock, etc.)
    profile.push_str("(allow network-bind)\n");
    profile.push_str("(allow network-inbound)\n");

    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_profile_basic() {
        let closure = vec![PathBuf::from("/nix/store/abc-bash-5.0")];
        let workspace = PathBuf::from("/tmp/workspace");
        let root = PathBuf::from("/tmp/root");
        let profile = generate_profile(&closure, &workspace, &root, Some(3128));

        // Should contain deny-by-default
        assert!(profile.contains("(deny default)"));

        // Should allow reading from closure
        assert!(profile.contains("/nix/store/abc-bash-5.0"));

        // Should allow workspace access
        assert!(profile.contains("/tmp/workspace"));

        // Should mention proxy port in comments
        assert!(profile.contains("3128"));

        // Should allow reading from root dir for CA cert
        assert!(profile.contains("/tmp/root"));
    }

    #[test]
    fn test_generate_profile_multiple_closure_paths() {
        let closure = vec![
            PathBuf::from("/nix/store/abc-bash-5.0"),
            PathBuf::from("/nix/store/def-coreutils-9.0"),
        ];
        let workspace = PathBuf::from("/tmp/workspace");
        let root = PathBuf::from("/tmp/root");
        let profile = generate_profile(&closure, &workspace, &root, Some(3128));

        // Should contain all closure paths
        assert!(profile.contains("/nix/store/abc-bash-5.0"));
        assert!(profile.contains("/nix/store/def-coreutils-9.0"));
    }

    #[test]
    fn test_generate_profile_contains_essential_rules() {
        let closure = vec![PathBuf::from("/nix/store/abc-bash-5.0")];
        let workspace = PathBuf::from("/tmp/workspace");
        let root = PathBuf::from("/tmp/root");
        let profile = generate_profile(&closure, &workspace, &root, Some(3128));

        // Should have essential system access
        assert!(profile.contains("(allow sysctl-read)"));
        assert!(profile.contains("(allow process-fork)"));
        assert!(profile.contains("(allow signal)"));

        // Should have network restrictions
        assert!(profile.contains("localhost"));
    }

    #[test]
    fn test_generate_profile_without_proxy() {
        let closure = vec![PathBuf::from("/nix/store/abc-bash-5.0")];
        let workspace = PathBuf::from("/tmp/workspace");
        let root = PathBuf::from("/tmp/root");
        let profile = generate_profile(&closure, &workspace, &root, None);

        // Should contain deny-by-default
        assert!(profile.contains("(deny default)"));

        // Should NOT allow network access
        assert!(!profile.contains("localhost"));
        assert!(profile.contains("completely blocked"));

        // Should NOT allow reading from root dir when proxy is disabled
        assert!(!profile.contains("/tmp/root"));
    }
}
