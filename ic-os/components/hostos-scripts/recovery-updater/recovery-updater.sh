#!/bin/bash

set -e

# Function to extract a value from /proc/cmdline
get_cmdline_var() {
    local var="$1"
    grep -oP "${var}=[^ ]*" /proc/cmdline | head -n1 | cut -d= -f2-
}

URL="$(get_cmdline_var url)"
TARGET_HASH="$(get_cmdline_var hash)"

echo "=== Recovery Updater Started ==="
echo "URL: $URL"
echo "Target Hash: $TARGET_HASH"
echo "==============================="

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading upgrade from $URL..."
if ! curl -L -o "$TMPDIR/upgrade.tar.zst" "$URL"; then
    echo "Failed to download upgrade file"
    exit 1
fi

echo "Verifying upgrade image hash..."
ACTUAL_HASH=$(sha256sum "$TMPDIR/upgrade.tar.zst" | cut -d' ' -f1)
if [ "$ACTUAL_HASH" != "$TARGET_HASH" ]; then
    echo "Hash verification failed"
    echo "Expected: $TARGET_HASH"
    echo "Got: $ACTUAL_HASH"
    exit 1
fi

echo "Hash verification successful"

# Extract the upgrade file
zstd -d "$TMPDIR/upgrade.tar.zst" -o "$TMPDIR/upgrade.tar"
tar -xf "$TMPDIR/upgrade.tar" -C "$TMPDIR"

# Install the upgrade using manageboot
/opt/ic/bin/manageboot.sh guestos upgrade-install "$TMPDIR/boot.img" "$TMPDIR/root.img"

echo "Upgrade installation complete"
