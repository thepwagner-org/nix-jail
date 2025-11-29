#!/usr/bin/env bash
# Tests automatic PR creation with the --push flag
#
# This script demonstrates how nix-jail can automatically:
# 1. Detect commits made during job execution
# 2. Create a new branch (job-${jobID})
# 3. Push the branch to GitHub
# 4. Create a pull request to the original branch
#
# Run with:
#   cargo run --bin client -- exec -p bash -p git \
#     --repo https://github.com/wapwagner/mtd \
#     --ref main \
#     --push \
#     -s examples/scripts/pr-test.sh \
#     --policy examples/network-policies/github-allow.toml
#
# Note: Requires GitHub credential configured in server config

set -e

echo "=== Auto-PR Test ==="
echo ""

# Configure git (required for committing)
git config user.name "nix-jail-bot"
git config user.email "nix-jail@example.com"

echo "=== Current Git Status ==="
git status
echo ""

echo "=== Creating Random Commit ==="
# Job commits directly to current branch (main)
# nix-jail orchestrator will automatically create a branch for the PR
echo $RANDOM > MEOW.md
git add MEOW.md
git commit -m "meow: random commit $RANDOM from nix-jail"

echo ""
echo "=== Commit created successfully ==="
git log -1 --oneline
echo ""
echo "After job completion, nix-jail will:"
echo "  1. Detect this commit"
echo "  2. Create branch job-\${jobID}"
echo "  3. Push to GitHub"
echo "  4. Create pull request to main"
echo ""
