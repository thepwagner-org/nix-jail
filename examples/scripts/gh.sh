#!/usr/bin/env bash
# Tests GitHub token fingerprinting with credential injection
#
# NOTE: Can't use `gh` CLI on macOS - it's a Go binary and Go on macOS uses the
# system certificate store (Security.framework) instead of SSL_CERT_FILE.
# This should work with `gh` on Linux where Go respects SSL_CERT_FILE.
#
# Run (denied - no policy):
#   cargo run --bin client -- exec -p bash -p curl -p jq -s examples/scripts/gh.sh
#
# Run (allowed - with credential injection):
#   cargo run --bin client -- exec -p bash -p curl -p jq -s examples/scripts/gh.sh --policy examples/network-policies/github-allow.toml

set -e

echo "=== GitHub Token Fingerprint ==="
echo "GITHUB_TOKEN: $GITHUB_TOKEN"
echo ""

echo "=== Authenticated User ==="
curl -s -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/user | jq '{login, name, email, type}'
echo ""

echo "=== gh CLI ==="
if gh --version; then
  gh api /user | jq '{login, name, email, type}'
  echo ""
fi

echo "=== Test Complete ==="
