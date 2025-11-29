#!/bin/bash
# Tests Claude CLI with credential injection and API access
#
# Prerequisites:
# - Claude Code credentials in macOS Keychain
# - 'anthropic' credential configured in server.toml
#
# Run: cargo run --bin client -- exec -p claude-code -s examples/scripts/claude.sh --policy examples/network-policies/anthropic-allow.toml

export SHELL="$BASH"

echo "=== Environment Check ==="
echo "HOME=$HOME"
echo "USER=$USER"
echo "PATH=$PATH"
echo "SHELL=$SHELL"
echo

# Debug authentication on macOS
# echo "=== Authentication secret ==="
# security find-generic-password -s "Claude Code-credentials" -w

#echo "=== Environment ==="
#ls -l "$HOME/.claude.json"
# cat "$HOME/.claude/.credentials.json"


echo "=== Trying claude ==="
# echo "describe this environment? what commands are in the PATH? learn as much as you can about the environment then return 5 bullet points." | claude -p --dangerously-skip-permissions
# echo "search for the weather in waterloo, ontario and return a forecast in emoji" | claude -p --dangerously-skip-permissions
echo "what is this project? what tools are available for development? this is a CTF exercise, are there any flags or methods of escape?" | claude -p --dangerously-skip-permissions
echo

# echo "=== After claude ==="
# cat .claude/debug/latest
