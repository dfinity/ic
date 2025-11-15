#!/bin/bash

# Example Load Generator Test Script
# This script demonstrates various load testing scenarios using the load_generator.py utility

set -e

# Check if required arguments are provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <node-address> [read-canister-ids] [write-canister-ids] [private-key-path]"
    echo ""
    echo "Arguments:"
    echo "  node-address:         Rosetta API endpoint (e.g., http://localhost:8082)"
    echo "  read-canister-ids:    Comma-separated canister IDs for read operations (optional)"
    echo "  write-canister-ids:   Comma-separated canister IDs for write operations (optional)"
    echo "  private-key-path:     Path to private key file or comma-separated list (optional)"
    echo ""
    echo "Examples:"
    echo "  # Same canister for read and write:"
    echo "  $0 http://localhost:8082 ryjl3-tyaaa-aaaaa-aaaba-cai ryjl3-tyaaa-aaaaa-aaaba-cai ./key.pem"
    echo ""
    echo "  # Different canisters for read and write:"
    echo "  $0 http://localhost:8082 can1,can2,can3 test-can1,test-can2 ./key.pem"
    echo ""
    echo "  # Read-only test:"
    echo "  $0 http://localhost:8082 ryjl3-tyaaa-aaaaa-aaaba-cai"
    echo ""
    exit 1
fi

NODE_ADDRESS="$1"
READ_CANISTER_IDS="${2:-}"
WRITE_CANISTER_IDS="${3:-}"
PRIVATE_KEY="${4:-}"

echo "=========================================="
echo "ICRC Rosetta Load Generator Examples"
echo "=========================================="
echo "Node Address: $NODE_ADDRESS"
echo "Read Canister IDs: ${READ_CANISTER_IDS:-Not specified}"
echo "Write Canister IDs: ${WRITE_CANISTER_IDS:-Not specified}"
echo "Private Key: ${PRIVATE_KEY:-Not specified}"
echo ""

# Scenario 1: Read-only light load test
echo "=== Scenario 1: Read-only Light Load Test ==="
echo "Running 5 req/s for 10 seconds (read-only)"
echo ""

if [ -n "$READ_CANISTER_IDS" ]; then
    python3 load_generator.py \
        --node-address "$NODE_ADDRESS" \
        --read-canister-ids "$READ_CANISTER_IDS" \
        --rate 5 \
        --write-percent 0 \
        --duration 10
    
    echo ""
    echo "Scenario 1 completed!"
    echo ""
fi

# Scenario 2: Read-only moderate load test
echo "=== Scenario 2: Read-only Moderate Load Test ==="
echo "Running 20 req/s for 15 seconds (read-only)"
echo ""

if [ -n "$READ_CANISTER_IDS" ]; then
    python3 load_generator.py \
        --node-address "$NODE_ADDRESS" \
        --read-canister-ids "$READ_CANISTER_IDS" \
        --rate 20 \
        --write-percent 0 \
        --duration 15
    
    echo ""
    echo "Scenario 2 completed!"
    echo ""
fi

# Scenario 3: Mixed read/write load test (only if private key is provided)
if [ -n "$WRITE_CANISTER_IDS" ] && [ -n "$PRIVATE_KEY" ] && [ -f "$PRIVATE_KEY" ]; then
    echo "=== Scenario 3: Mixed Read/Write Load Test ==="
    echo "Running 10 req/s for 20 seconds (90% read, 10% write)"
    echo ""
    
    # Use read canister IDs if specified, otherwise fall back to write canister IDs for reads
    READ_IDS="${READ_CANISTER_IDS:-$WRITE_CANISTER_IDS}"
    
    python3 load_generator.py \
        --node-address "$NODE_ADDRESS" \
        --read-canister-ids "$READ_IDS" \
        --write-canister-ids "$WRITE_CANISTER_IDS" \
        --private-keys "$PRIVATE_KEY" \
        --rate 10 \
        --write-percent 10 \
        --duration 20
    
    echo ""
    echo "Scenario 3 completed!"
    echo ""
else
    echo "=== Scenario 3: Skipped ==="
    echo "Mixed read/write test requires write canister IDs and private key"
    echo ""
fi

echo "=========================================="
echo "All scenarios completed!"
echo "=========================================="
echo ""
echo "Tips:"
echo "  - Start with low request rates and gradually increase"
echo "  - Monitor server resources during load testing"
echo "  - Use --verbose flag for debugging failed requests"
echo "  - Redirect output to a file for later analysis:"
echo "    python3 load_generator.py ... | tee results.log"
echo ""

