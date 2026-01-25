# nix-jail Testing Guide

Complete guide to testing nix-jail across all supported platforms and executors.

## Setup

```fish
cargo build && alias nj target/debug/client
```

## Supported Executors

| Platform | Executor | Command |
|----------|----------|---------|
| macOS | sandbox-exec (default) | `nj run ...` |
| macOS | Docker | `nj run --executor docker ...` |
| Linux | systemd-run (default) | `nj run ...` |
| Linux | Docker | `nj run --executor docker ...` |

## Quick Smoke Test

The simplest test to verify nj works:

```bash
# Should print a cow saying "moo"
nj run -p cowsay -- cowsay moo

# Multiple packages
nj run -p cowsay -p figlet -- bash -c 'figlet "moo" | cowsay -n'

# No network by default
nj run -p curl -- curl -v https://httpbin.org/get

# Allow a specific host - that certificate sure looks fresh!
# (network access uses namespaces and requires sudo)
nj run -p curl --allow-host httpbin.org -- curl -v https://httpbin.org/get

# Real token not leaked to environment (shows dummy value from config)
FAKE_TOKEN_WILL_BE_LEAKED=hunter2 nj run -p coreutils \
  --config examples/credentials/httpbin-demo.toml \
  --policy examples/network-policies/httpbin-demo.toml -- env

# Proxy injects real token into requests
FAKE_TOKEN_WILL_BE_LEAKED=hunter2 nj run -p curl -p bash \
  --config examples/credentials/httpbin-demo.toml \
  --policy examples/network-policies/httpbin-demo.toml \
  -- bash -c 'curl -s -H "Authorization: Bearer $FAKE_TOKEN_WILL_BE_LEAKED" https://httpbin.org/headers'

# Only if the request included the dummy token
FAKE_TOKEN_WILL_BE_LEAKED=hunter2 nj run -p curl \
  --config examples/credentials/httpbin-demo.toml \
  --policy examples/network-policies/httpbin-demo.toml \
  -- curl -s -H "Authorization: just-trust-me-bro" https://httpbin.org/headers

# Wow this is cool I want to poke around
nj run -p coreutils -p zsh -i -- zsh
```

## Testing Executors

### macOS (sandbox-exec)

```bash
# Current directory is readable
nj run -p coreutils -- ls -l

# Rest of the system is not
nj run -p coreutils -- ls /nix/store/
nj run -p coreutils -- ls ~

# Only the relevant paths of the nix store are available
nj run -p coreutils -p which -- which ls
```

### Linux (systemd-run)

```bash
# Current directory is readable
nj run -p coreutils -- ls -l

# Chroot-ed from rest of the system
nj run -p coreutils -- ls ~

# Nix store is listable, but trimmed to only required paths
nj run -p coreutils -- ls /nix/store/
```

### Docker

```bash
# Current directory is readable
nj run --executor docker -p coreutils -- ls -l

# Nix store is listable, but trimmed to only required paths
nj run --executor docker -p coreutils -- ls /nix/store/
```

## Disk Cache Testing

Package resolution is cached to disk for CLI mode.

```bash
# First run - cache miss, runs nix-build (~330ms)
RUST_LOG=debug nj run -p cowsay -- cowsay "First"
# Look for: "cache miss - resolving packages"

# Second run - L2 cache hit (~1ms)
RUST_LOG=debug nj run -p cowsay -- cowsay "Second"
# Look for: "L2 cache hit (disk) - promoting to L1"

# Cache location
ls ~/.local/share/nix-jail/packages/
```

## Interactive Mode Testing

Interactive mode (`-i` flag) allocates a PTY, letting you "be inside" the sandbox.

### macOS + sandbox-exec

```bash
# Interactive zsh shell
nj run -p zsh -p coreutils -i -- zsh

# With working directory
nj run -p zsh -p coreutils -i -w /path/to/project -- zsh
```

### macOS + Docker

```bash
# Interactive shell in Docker
nj run --executor docker -p zsh -p coreutils -i -- zsh
```

### Linux + systemd

```bash
# Interactive zsh shell (requires root for systemd-run)
sudo nj run -p zsh -p coreutils -i -- zsh

# Or with bash
sudo nj run -p bash -p coreutils -i -- bash
```

### Linux + Docker

```bash
# Interactive shell in Docker
nj run --executor docker -p zsh -p coreutils -i -- zsh
```

## Flake Support

```bash
# Project with flake.nix - closure computed from devShell
cd /path/to/flake-project
nj run -- bash -c 'echo "Using flake closure"'
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
nj run --executor docker \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  -p bash -p git \
  -- bash -c "pwd && ls -la"
```

### Test 2: Verify sparse checkout

```bash
# Should show only the requested path, minimal objects
nj run --executor docker \
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
time nj run --executor docker \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  -p bash -- echo "First run"

# Second run - should be instant (volume cache hit)
time nj run --executor docker \
  --repo "$REPO" \
  --path "projects/nix-jail" \
  -p bash -- echo "Second run (cached)"
```

### Test 4: Specific git ref

```bash
# Checkout a specific commit
nj run --executor docker \
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
