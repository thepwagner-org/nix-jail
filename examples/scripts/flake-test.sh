#!/usr/bin/env bash
# Tests flake.nix detection and environment
#
# Run with: cargo run --bin client -- exec -p bash --repo https://github.com/wapwagner/mtd -s examples/scripts/flake-test.sh

echo "=== Flake Environment Test ==="
echo ""

echo "=== Working Directory ==="
pwd
echo ""

echo "=== Check for flake.nix ==="
if [ -f flake.nix ]; then
    echo "✓ flake.nix found"
else
    echo "✗ flake.nix NOT found"
fi
echo ""

echo "=== Available Commands ==="
echo -n "go: "
if command -v go &> /dev/null; then
    go version
else
    echo "(go not available)"
fi

echo -n "golangci-lint: "
if command -v golangci-lint &> /dev/null; then
    golangci-lint version
else
    echo "(golangci-lint not available)"
fi
echo ""

echo -n "prettier: "
if command -v prettier &> /dev/null; then
    prettier --version
else
    echo "(prettier not available)"
fi
echo ""

echo "=== PATH ==="
echo "$PATH" | tr ':' '\n'
echo ""

echo "what is this project, is it any good?" | claude -p --dangerously-skip-permissions

echo "=== Test Complete ==="
