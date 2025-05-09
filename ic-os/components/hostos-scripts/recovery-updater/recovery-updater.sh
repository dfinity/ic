#!/bin/bash

set -e

# Perform a manual GuestOS upgrade from the HostOS

# Helper function to extract a value from /proc/cmdline
get_cmdline_var() {
    local var="$1"
    grep -oP "${var}=[^ ]*" /proc/cmdline | head -n1 | cut -d= -f2-
}

# Get partition targets based on boot alternative
get_partition_targets() {
    local lodev="$1"
    local boot_alternative="$2"

    if [ "$boot_alternative" = "A" ]; then
        echo "${lodev}p7 ${lodev}p8 ${lodev}p9"
    else
        echo "${lodev}p4 ${lodev}p5 ${lodev}p6"
    fi
}

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

    # Get partition targets
    read -r boot_target root_target var_target < <(get_partition_targets "$lodev" "$boot_alternative")
    echo "Target boot partition: $boot_target"
    echo "Target root partition: $root_target"
    echo "Target var partition: $var_target"
}

function download_and_verify_upgrade() {
    local url="$1"
    local target_hash="$2"
    local tmpdir="$3"

    echo "Downloading upgrade from $url..."
    if ! curl -L -o "$tmpdir/upgrade.tar.zst" "$url"; then
        echo "ERROR: Failed to download upgrade file"
        exit 1
    fi
    echo "Download completed successfully"

    echo "Verifying upgrade image hash..."
    local actual_hash=$(sha256sum "$tmpdir/upgrade.tar.zst" | cut -d' ' -f1)
    if [ "$actual_hash" != "$target_hash" ]; then
        echo "ERROR: Hash verification failed"
        echo "Expected: $target_hash"
        echo "Got: $actual_hash"
        exit 1
    fi
    echo "Hash verification successful"
}

function extract_upgrade() {
    local tmpdir="$1"
    echo "Extracting upgrade file..."
    zstd -d "$tmpdir/upgrade.tar.zst" -o "$tmpdir/upgrade.tar"
    tar -xf "$tmpdir/upgrade.tar" -C "$tmpdir"
    echo "Extraction completed"
}

function install_upgrade() {
    local tmpdir="$1"
    echo "Installing upgrade using manageboot..."
    /opt/ic/bin/manageboot_recovery.sh upgrade-install \
        "${grubdir}/grubenv" \
        "${boot_target}" \
        "${root_target}" \
        "${var_target}" \
        "$tmpdir/boot.img" \
        "$tmpdir/root.img"
    echo "Upgrade installation complete"
}

function guestos_upgrade_cleanup() {
    echo "Starting cleanup"
    if [ -n "${grubdir}" ] && mountpoint -q "${grubdir}"; then
        umount "${grubdir}"
        echo "Unmounted ${grubdir}"
    fi
    if [ -n "${workdir}" ] && [ -d "${workdir}" ]; then
        rm -rf "${workdir}"
        echo "Removed temporary directory ${workdir}"
    fi
}

main() {
    echo "Starting GuestOS recovery updater"

    URL="$(get_cmdline_var url)"
    TARGET_HASH="$(get_cmdline_var hash)"
    echo "Download url: $URL"
    echo "Download hash: $TARGET_HASH"

    TMPDIR=$(mktemp -d)
    trap 'guestos_upgrade_cleanup; rm -rf "$TMPDIR"' EXIT

    prepare_guestos_upgrade
    download_and_verify_upgrade "$URL" "$TARGET_HASH" "$TMPDIR"
    extract_upgrade "$TMPDIR"
    install_upgrade "$TMPDIR"

    echo "Recovery updater completed successfully"

    echo "Rebooting GuestOS into new version..."
    systemctl restart guestos
}

main
