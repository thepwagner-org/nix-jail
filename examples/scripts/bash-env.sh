#!/usr/bin/env sh
# Tests basic sandbox functionality - no network required
#
# Run (all packages): cargo run --bin client -- exec -p bash -p coreutils -p which -s examples/scripts/bash-env.sh
# Run (restricted): cargo run --bin client -- exec -p bash -s examples/scripts/bash-env.sh

echo "=== Environment Variables ==="
env
#echo "HTTP_PROXY=$HTTP_PROXY"
#echo "HTTPS_PROXY=$HTTPS_PROXY"
#echo "SSL_CERT_FILE=$SSL_CERT_FILE"
#echo "NO_PROXY=$NO_PROXY"
#echo "PATH=$PATH"
echo ls -l  $SSL_CERT_FILE
ls -l  $SSL_CERT_FILE
echo ""

#echo ""
#echo "=== Available Commands ==="
#which bash
#which env
#which ls

#echo ""
#echo "=== nix store ==="
#ls -la /nix/store
#echo ""

echo "=== Working Directory ==="
pwd
ls -la
echo ""

#echo "=== Tree==="
#tree -d -L 2 /
#echo ""


echo "=== Test Complete ==="
