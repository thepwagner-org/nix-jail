# nix-jail Testing Guide

Complete guide to testing nix-jail across all supported platforms and executors.

## Supported Executors

| Platform | Executor | Command |
|----------|----------|---------|
| macOS | sandbox-exec (default) | `nix-jail run ...` |
| macOS | Docker | `nix-jail run --executor docker ...` |
| Linux | systemd-run (default) | `nix-jail run ...` |
| Linux | Docker | `nix-jail run --executor docker ...` |

## Quick Smoke Test

The simplest test to verify nix-jail works:

```bash
# Should print a cow saying "moo"
nix-jail run -p cowsay -- cowsay moo
```

## Testing Each Executor

### macOS + sandbox-exec (default)

```bash
# Basic execution
nix-jail run -p cowsay -- cowsay "Hello from sandbox-exec"

# With multiple packages
nix-jail run -p cowsay -p figlet -- bash -c 'figlet "Hi" | cowsay -n'

# Verify sandbox isolation (should fail to access home directory)
nix-jail run -p coreutils -- ls ~/
```

### macOS + Docker

macOS requires `--store-strategy docker-volume` because /nix/store can't be bind-mounted into Docker.

```bash
# Basic execution (uses busybox container with Nix closure in Docker volume)
nix-jail run --executor docker --store-strategy docker-volume -p cowsay -- cowsay "Hello from Docker"

# Verify Docker volume caching (second run should be faster)
time nix-jail run --executor docker --store-strategy docker-volume -p cowsay -- cowsay "First run"
time nix-jail run --executor docker --store-strategy docker-volume -p cowsay -- cowsay "Second run (cached)"
```

### Linux + systemd-run (default)

```bash
# Basic execution
nix-jail run -p cowsay -- cowsay "Hello from systemd"

# With JIT runtime (for Node.js, Python, etc.)
nix-jail run -p nodejs --hardening-profile jit-runtime -- node -e 'console.log("Hello from Node")'

# Running as non-root (requires polkit configuration)
# See NixOS setup below
```

### Linux + Docker

```bash
# Basic execution
nix-jail run --executor docker -p cowsay -- cowsay "Hello from Docker on Linux"
```

## Network Policy Testing

Network access is denied by default. Use policies to allow specific hosts.

### Test 1: Default deny

```bash
# Should fail with connection error
nix-jail run -p curl -- curl -s https://httpbin.org/get
```

### Test 2: Allow specific host

```bash
# Should succeed
nix-jail run -p curl --allow-host "httpbin.org" -- curl -s https://httpbin.org/get
```

### Test 3: Policy file with path filtering

```bash
# examples/network-policies/httpbin-allow.toml allows only /get path
nix-jail run -p curl --policy examples/network-policies/httpbin-allow.toml \
  -- curl -s https://httpbin.org/get    # allowed

nix-jail run -p curl --policy examples/network-policies/httpbin-allow.toml \
  -- curl -s https://httpbin.org/post   # blocked
```

### Test 4: Credential injection

```bash
# GitHub API with token injection
nix-jail run -p curl -p jq \
  --policy examples/network-policies/github-allow.toml \
  -- bash -c 'curl -s https://api.github.com/user | jq .login'
```

### Test 5: Ephemeral credentials (gRPC only)

Ephemeral credentials are client-provided, short-lived tokens passed in the JobRequest.
They exist only in memory for the job's lifetime and are never persisted.

**When testing features that use ephemeral credentials, verify:**

1. The token is correctly injected into matching requests
2. **The token value NEVER appears in streamed logs** - search all output carefully
3. The token is not persisted in job metadata (check SQLite database)
4. Ephemeral credentials with the same name override server credentials (warning logged)

**Security verification checklist:**

- Run a job with an ephemeral credential and capture all output
- Search the output for any substring of the token value
- Verify the token does not appear anywhere in logs, errors, or debug output
- Check that `CredentialSource::Inline` cannot be serialized (serde skip)

## Disk Cache Testing

Package resolution is cached to disk for CLI mode.

```bash
# First run - cache miss, runs nix-build (~330ms)
RUST_LOG=debug nix-jail run -p cowsay -- cowsay "First"
# Look for: "cache miss - resolving packages"

# Second run - L2 cache hit (~1ms)
RUST_LOG=debug nix-jail run -p cowsay -- cowsay "Second"
# Look for: "L2 cache hit (disk) - promoting to L1"

# Cache location
ls ~/.local/share/nix-jail/packages/
```

## Interactive Mode Testing

```bash
# Interactive shell
nix-jail run -p bash -p coreutils -it -- bash

# With working directory
nix-jail run -p bash -p coreutils -it -w /path/to/project -- bash
```

## Flake Support

```bash
# Project with flake.nix - closure computed from devShell
cd /path/to/flake-project
nix-jail run -- bash -c 'echo "Using flake closure"'
```

## Git Workspace Testing

Test sparse checkout of remote repositories into Docker volumes.

```bash
# Set your repo URL
REPO="https://user:TOKEN@git.example.com/org/repo.git"  # trufflehog:ignore
```

### Test 1: Basic git workspace

```bash
# Clone a subpath from a monorepo
nix-jail run --executor docker --store-strategy docker-volume \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  -p bash -p git \
  -- bash -c "pwd && ls -la"
```

### Test 2: Verify sparse checkout

```bash
# Should show only the requested path, minimal objects
nix-jail run --executor docker --store-strategy docker-volume \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  -p bash -p git \
  -- bash -c '
echo "=== Sparse checkout path ==="
git sparse-checkout list

echo "=== Git objects (should be minimal) ==="
git count-objects -v
'
```

### Test 3: Volume caching

```bash
# First run - creates volume
time nix-jail run --executor docker --store-strategy docker-volume \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  -p bash -- echo "First run"

# Second run - should be instant (volume cache hit)
time nix-jail run --executor docker --store-strategy docker-volume \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  -p bash -- echo "Second run (cached)"
```

### Test 4: Specific git ref

```bash
# Checkout a specific commit
nix-jail run --executor docker --store-strategy docker-volume \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  --git-ref "main" \
  -p bash -p git \
  -- git log -1 --oneline
```

## Platform-Specific Setup

### NixOS: polkit for non-root systemd-run

Add to `configuration.nix`:

```nix
security.polkit = {
  enable = true;
  extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "org.freedesktop.systemd1.manage-units" &&
          subject.user == "youruser") {
        return polkit.Result.YES;
      }
    });
  '';
};
```

### macOS: Docker Desktop

Ensure Docker Desktop is running for Docker executor tests.

## Server Mode Testing

For testing the gRPC server (used by GitHub Actions integration):

```bash
# Terminal 1: Start server
cargo build && cargo run --bin server -- --config server.toml

# Terminal 2: Submit job via client
cargo run --bin client -- exec -p cowsay -s examples/scripts/cowsay-test.sh
```

## Distributed Tracing

nix-jail supports OpenTelemetry tracing. To enable server-side tracing, add to `server.toml`:

```toml
[server]
otlp_endpoint = "http://tempo.example.com:4317"
```

## Troubleshooting

### "Permission denied" on Linux cleanup

If running as non-root via polkit, ensure the cleanup fix is applied.

### Docker volume not found

```bash
# List volumes
docker volume ls | grep nix-jail

# Clean up orphaned volumes
docker volume prune
```

### Locale warnings

Jobs now run with `LANG=C`.

## See Also

- [SANDBOX.md](SANDBOX.md) - Sandbox architecture and security model
- [CLAUDE.md](CLAUDE.md) - Development guide and security rules
