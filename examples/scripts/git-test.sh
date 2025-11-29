#!/usr/bin/env bash
# Tests git workspace functionality
#
# Run (with git): cargo run --bin client -- exec -p bash -p git -p coreutils --repo https://github.com/thepwagner/dotfiles -s examples/scripts/git-test.sh
# Run (without git): cargo run --bin client -- exec -p bash -p coreutils --repo https://github.com/thepwagner/dotfiles -s examples/scripts/git-test.sh

echo "=== Git Workspace Test ==="
echo ""

echo "=== Working Directory ==="
pwd
echo ""

echo "=== Repository Contents ==="
ls -la
echo ""


if command -v git &> /dev/null; then
    echo "=== Git Information (git package available) ==="
    echo -n "Branch:"
    git branch --show-current 2>/dev/null || echo "(detached HEAD or error)"
    echo ""
    echo -n "Commit:"
    git log -1 --oneline 2>/dev/null || echo "(error reading git log)"
    echo ""
    echo -n "Remote:"
    git remote -v 2>/dev/null || echo "(no remote configured)"
fi
echo ""
echo "=== Test Complete ==="
