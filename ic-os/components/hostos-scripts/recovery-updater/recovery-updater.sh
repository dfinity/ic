#!/bin/bash

set -e

# Perform a manual GuestOS upgrade from the HostOS

# Constants for partitions and paths
GRUB_PARTITION_NUM=2
BOOT_PARTITION_A=4
ROOT_PARTITION_A=5
VAR_PARTITION_A=6
BOOT_PARTITION_B=7
ROOT_PARTITION_B=8
VAR_PARTITION_B=9

GUESTOS_DEVICE="/dev/hostlvm/guestos"
MANAGEBOOT_SCRIPT="/opt/ic/bin/manageboot.sh"

# Helper function to extract a value from /proc/cmdline
get_cmdline_var() {
    local var="$1"
    grep -oP "${var}=[^ ]*" /proc/cmdline | head -n1 | cut -d= -f2-
}

# Get partition targets based on boot alternative (help: should it be the other system?)
get_partition_targets() {
    local lodev="$1"
    local boot_alternative="$2"

    # boot_alternative is the system that is *currently running*
    if [ "$boot_alternative" = "A" ]; then
        echo "${lodev}p${BOOT_PARTITION_B} ${lodev}p${ROOT_PARTITION_B} ${lodev}p${VAR_PARTITION_B}"
    else
        echo "${lodev}p${BOOT_PARTITION_A} ${lodev}p${ROOT_PARTITION_A} ${lodev}p${VAR_PARTITION_A}"
    fi
}

# Upgrade and boot into the alternative boot partition (help: reverse this?)
function prepare_guestos_upgrade() {
    echo "Starting guestos upgrade preparation"
    lodev="$(losetup -Pf --show ${GUESTOS_DEVICE})"
    echo "Set up loop device: $lodev"

    workdir="$(mktemp -d)"
    grubdir="${workdir}/grub"
    bootdir="${workdir}/boot"
    rootdir="${workdir}/root"
    mkdir "${grubdir}" "${bootdir}" "${rootdir}"
    echo "Created temporary directories in $workdir"

    mount -o rw,sync "${lodev}p${GRUB_PARTITION_NUM}" "${grubdir}"
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
    ${MANAGEBOOT_SCRIPT} upgrade-recovery \
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
