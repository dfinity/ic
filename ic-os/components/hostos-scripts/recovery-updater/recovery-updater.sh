#!/bin/bash

set -e

# Upgrade and boot into the alternative boot partition (help: reverse this?)
function prepare_guestos_upgrade() {
    echo "Starting guestos upgrade preparation"
    lodev="$(losetup -Pf --show /dev/hostlvm/guestos)"
    echo "Set up loop device: $lodev"
    
    workdir="$(mktemp -d)"
    grubdir="${workdir}/grub"
    bootdir="${workdir}/boot"
    rootdir="${workdir}/root"
    mkdir "${grubdir}" "${bootdir}" "${rootdir}"
    echo "Created temporary directories in $workdir"

    mount -o rw,sync "${lodev}p2" "${grubdir}"
    echo "Mounted grub partition at ${grubdir}"

    # Get the boot alternative
    boot_alternative="$(grep -oP '^boot_alternative=\K[a-zA-Z]+' "${grubdir}/grubenv")"
    echo "Current boot alternative: $boot_alternative"

    # Choose the targets of the inactive partitions
    if [ "$boot_alternative" = "A" ]; then
        boot_target="${lodev}p7"
        root_target="${lodev}p8"
        var_target="${lodev}p9"
    else
        boot_target="${lodev}p4"
        root_target="${lodev}p5"
        var_target="${lodev}p6"
    fi
    echo "Target boot partition: $boot_target"
    echo "Target root partition: $root_target"
    echo "Target var partition: $var_target"
}

function guestos_upgrade_cleanup() {
    echo "Starting cleanup"
    umount "${grubdir}"
    echo "Unmounted ${grubdir}"
    rm -rf "${workdir}"
    echo "Removed temporary directory ${workdir}"
}

prepare_guestos_upgrade

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
echo "Created temporary directory: $TMPDIR"

echo "Downloading upgrade from $URL..."
if ! curl -L -o "$TMPDIR/upgrade.tar.zst" "$URL"; then
    echo "ERROR: Failed to download upgrade file"
    exit 1
fi
echo "Download completed successfully"

echo "Verifying upgrade image hash..."
ACTUAL_HASH=$(sha256sum "$TMPDIR/upgrade.tar.zst" | cut -d' ' -f1)
if [ "$ACTUAL_HASH" != "$TARGET_HASH" ]; then
    echo "ERROR: Hash verification failed"
    echo "Expected: $TARGET_HASH"
    echo "Got: $ACTUAL_HASH"
    exit 1
fi
echo "Hash verification successful"

echo "Extracting upgrade file..."
zstd -d "$TMPDIR/upgrade.tar.zst" -o "$TMPDIR/upgrade.tar"
tar -xf "$TMPDIR/upgrade.tar" -C "$TMPDIR"
echo "Extraction completed"

echo "Installing upgrade using manageboot..."
/opt/ic/bin/manageboot_recovery.sh upgrade-install \
    "${grubdir}/grubenv" \
    "${boot_target}" \
    "${root_target}" \
    "${var_target}" \
    "$TMPDIR/boot.img" \
    "$TMPDIR/root.img"

# help: need to pass manageboot.sh boot_dir and root_dir? and grub_dir to update grub?

echo "Upgrade installation complete"

guestos_upgrade_cleanup
echo "Recovery updater completed successfully"

echo "Rebooting guestos..."
systemctl restart guestos