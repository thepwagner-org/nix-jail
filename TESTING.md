# nix-jail Testing Guide

Complete guide to testing nix-jail with examples demonstrating network policies, credential injection, and sandbox isolation.

## Quick Start

### 1. Rebuild the proxy and start the server

```bash
cargo build && cargo run --bin server -- --config server.toml
```

### 2. Test Nix closure precision

```bash
# Test with all packages the script uses - full output
cargo run --bin client -- exec -p bash -p coreutils -p which -s examples/scripts/bash-env.sh

cargo run --bin client -- exec -p bash -p coreutils -s examples/scripts/bash-env.sh

cargo run --bin client -- exec -p bash -p coreutils -p which --nixpkgs nixos-unstable -s examples/scripts/bash-env.sh

# With only bash, we expect "which: command not found" and "ls: command not found"
cargo run --bin client -- exec -p bash -s examples/scripts/bash-env.sh
```

### 3. Test network policy enforcement

```bash
# Denied by default
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh

# Policy allows httpbin.org/get, blocks everything else
cat examples/network-policies/httpbin-allow.toml
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh \
  --policy examples/network-policies/httpbin-allow.toml

# Policy allows all
cat examples/network-policies/danger-allow-all.toml
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh \
  --policy examples/network-policies/danger-allow-all.toml

# Allowed by CLI (all paths on specified host)
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh \
  --allow-host "httpbin.org"
```

### 4. Test credential injection (Claude)

```bash
# List models (but fail httpbin.org requests)
cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh \
  --policy examples/network-policies/anthropic-allow.toml

# Get a poem from claude (macOS)
cargo run --bin client -- exec -p coreutils -p claude-code --nixpkgs nixos-unstable -s examples/scripts/claude.sh \
  --policy examples/network-policies/anthropic-allow.toml --hardening-profile jit-runtime

# Get a poem from claude (Linux)
cargo run --bin client -- exec -p coreutils -p claude-code --nixpkgs nixos-unstable -s examples/scripts/claude.sh \
  --policy examples/network-policies/anthropic-allow-linux.toml --hardening-profile jit-runtime
```

### 5. Test GitHub token injection and fingerprinting

```bash
# With GitHub credential injection
cargo run --bin client -- exec -p bash -p curl -p jq -s examples/scripts/gh.sh \
  --policy examples/network-policies/github-allow.toml

# On Linux, we can use the `gh` CLI (does not work on macOS)
cargo run --bin client -- exec -p bash -p curl -p jq -p gh -s examples/scripts/gh.sh \
  --policy examples/network-policies/github-allow.toml
```

### 6. Test Git Workspace

```bash
# Clone public repo and run script (with git package)
cargo run --bin client -- exec -p bash -p git -p coreutils \
  --repo https://github.com/thepwagner/dotfiles \
  -s examples/scripts/git-test.sh


# Run script from specific path in repo (if repo has subdirectories with scripts)
cargo run --bin client -- exec -p bash -p git -p coreutils \
  --repo https://github.com/thepwagner/dotfiles \
  --path .config  --ref 85e9ed3f532b6d7ea497bc1924a31920466d5a8a \
  -s examples/scripts/git-test.sh

cargo run --bin client -- exec \
  --repo https://github.com/wapwagner/mtd \
  --ref main \
  --push \
  -s examples/scripts/pr-claude.sh \
  --policy examples/network-policies/anthropic-allow.toml
```

## Distributed Tracing

nix-jail supports OpenTelemetry tracing via Tempo at `tempo.pwagner.net`.

The client sends traces by default. To enable server-side tracing, add to `server.toml`:

```toml
[server]
otlp_endpoint = "http://tempo.pwagner.net:4317"
```

## See Also

- [SANDBOX.md](SANDBOX.md) - Sandbox debugging guide
- [CLAUDE.md](CLAUDE.md) - Development guide and security rules
