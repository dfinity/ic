#!/usr/bin/env bash

# Wrapper script to run Rust integration tests with sudo
# This script re-executes itself with sudo if not already running as root

set -euo pipefail

# Check if running as root, if not re-execute with sudo
if [[ $EUID -ne 0 ]]; then
    echo "Not running as root, re-executing with sudo..."
    echo "Current directory: $PWD"
    echo "RUST_TEST_BIN: ${RUST_TEST_BIN:-<not set>}"
    echo "MKE2FS_BIN: ${MKE2FS_BIN:-<not set>}"

    # Preserve current working directory and re-execute with sudo
    # -E preserves environment variables
    # We need to cd to the current directory to maintain Bazel's test environment
    sudo -E bash -c "cd '$PWD' && exec '$0' $*"
    exit $?
fi

echo "Running as root (UID: $EUID) in directory: $PWD"

# Get the Rust test binary from environment variable
if [[ -z "${RUST_TEST_BIN:-}" ]]; then
    echo "Error: RUST_TEST_BIN environment variable not set"
    exit 1
fi

if [[ ! -x "$RUST_TEST_BIN" ]]; then
    echo "Error: Rust test binary not found or not executable: $RUST_TEST_BIN"
    exit 1
fi

echo "Running test binary: $RUST_TEST_BIN"
echo "MKE2FS_BIN: ${MKE2FS_BIN:-<not set>}"

# Check if loop devices are available
if [[ ! -e /dev/loop-control ]]; then
    echo "WARNING: /dev/loop-control not found, attempting to load loop module"
    modprobe loop || echo "WARNING: Failed to load loop module"
fi

echo "Available loop devices: $(ls -la /dev/loop* 2>/dev/null | wc -l)"

# Load filesystem kernel modules if not already loaded
echo "Loading filesystem kernel modules..."
modprobe vfat || echo "WARNING: Failed to load vfat module (may already be loaded)"
modprobe ext4 || echo "WARNING: Failed to load ext4 module (may already be loaded)"

# Check if modules are loaded
echo "Loaded filesystem modules:"
lsmod | grep -E "vfat|ext4|loop" || echo "No filesystem modules found in lsmod"

# Run the Rust test binary with all arguments passed through
exec "$RUST_TEST_BIN" "$@"

