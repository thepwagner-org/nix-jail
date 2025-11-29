#!/usr/bin/env bash
# Tests network policy enforcement with path-based filtering
#
# Run (denied): cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh
# Run (allowed): cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh --policy examples/network-policies/httpbin-allow.toml
# Run (CLI override): cargo run --bin client -- exec -p curl -s examples/scripts/curl.sh --allow-host "httpbin\\.org"


echo "=== Environment Variables ==="
echo "HTTP_PROXY=$HTTP_PROXY"
echo "HTTPS_PROXY=$HTTPS_PROXY"
echo "SSL_CERT_FILE=$SSL_CERT_FILE"
echo "NO_PROXY=$NO_PROXY"
echo ""

echo "=== Testing httpbin.org/get ==="
curl -s --max-time 2 https://httpbin.org/get
echo ""

echo "=== Testing httpbin.org/anything ==="
curl -s --max-time 2 https://httpbin.org/anything
echo ""

echo "=== Testing api.anthropic.com/v1/models ==="
curl -s --max-time 2 https://api.anthropic.com/v1/models/claude-sonnet-4-5
echo ""

echo "=== Test Complete ==="
