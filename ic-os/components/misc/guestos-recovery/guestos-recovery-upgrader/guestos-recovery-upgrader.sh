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

source /opt/ic/bin/grub.sh

# Helper function to extract a value from /proc/cmdline
get_cmdline_var() {
    local var="$1"
    grep -oP "${var}=[^ ]*" /proc/cmdline | head -n1 | cut -d= -f2-
}

get_upgrade_target_partitions() {
    local lodev="$1"
    local boot_alternative="$2"

    # boot_alternative is the system that is *currently running*
    if [ "$boot_alternative" = "A" ]; then
        echo "${lodev}p${BOOT_PARTITION_B} ${lodev}p${ROOT_PARTITION_B} ${lodev}p${VAR_PARTITION_B}"
    else
        echo "${lodev}p${BOOT_PARTITION_A} ${lodev}p${ROOT_PARTITION_A} ${lodev}p${VAR_PARTITION_A}"
    fi
}

prepare_guestos_upgrade() {
    echo "Starting guestos upgrade preparation"
    lodev="$(losetup -Pf --show ${GUESTOS_DEVICE})"
    echo "Set up loop device: $lodev"

    workdir="$(mktemp -d)"
    grubdir="${workdir}/boot/grub"
    mkdir -p "${grubdir}"
    echo "Created temporary directories in $workdir"

    mount -o rw,sync "${lodev}p${GRUB_PARTITION_NUM}" "${grubdir}"
    echo "Mounted grub partition at ${grubdir}"

    boot_alternative="$(grep -oP '^boot_alternative=\K[a-zA-Z]+' "${grubdir}/grubenv")"
    echo "Current boot alternative: $boot_alternative"

    # Get upgrade partition targets
    read -r boot_target root_target var_target < <(get_upgrade_target_partitions "$lodev" "$boot_alternative")
    echo "Target boot partition: $boot_target"
    echo "Target root partition: $root_target"
    echo "Target var partition: $var_target"
}

download_and_verify_upgrade() {
    local version="$1"
    local short_hash="$2"
    local tmpdir="$3"

    local base_urls=(
        "https://download.dfinity.systems/ic"
        "https://download.dfinity.network/ic"
    )

    local download_successful=false
    for base_url in "${base_urls[@]}"; do
        local url="${base_url}/${version}/guest-os/update-img/update-img.tar.zst"
        echo "Attempting to download upgrade from $url..."

        if curl -L -o "$tmpdir/upgrade.tar.zst" "$url"; then
            echo "Download from $base_url completed successfully"
            download_successful=true
            break
        else
            echo "WARNING: Failed to download from $base_url"
            # Remove partial download file if it exists
            rm -f "$tmpdir/upgrade.tar.zst"
        fi
    done

    if [ "$download_successful" = false ]; then
        echo "ERROR: Failed to download upgrade file from all available URLs"
        exit 1
    fi

    echo "Verifying upgrade image hash..."
    local actual_hash=$(sha256sum "$tmpdir/upgrade.tar.zst" | cut -d' ' -f1)
    local actual_short_hash=${actual_hash:0:6}
    if [ "$actual_short_hash" != "$short_hash" ]; then
        echo "ERROR: Hash verification failed"
        echo "Expected short 6-character hash: $short_hash"
        echo "Got short 6-character hash: $actual_short_hash"
        echo "Full hash: $actual_hash"
        exit 1
    fi
    echo "Hash verification successful"
}

extract_upgrade() {
    local tmpdir="$1"
    echo "Extracting upgrade file..."
    zstd -d "$tmpdir/upgrade.tar.zst" -o "$tmpdir/upgrade.tar"
    tar -xf "$tmpdir/upgrade.tar" -C "$tmpdir"
    echo "Extraction completed"
}

install_upgrade() {
    local tmpdir="$1"
    echo "Installing upgrade..."

    echo "=== Recovery Upgrader Mode ==="
    echo "Grubenv file: ${grubdir}/grubenv"
    echo "Boot device: ${boot_target}"
    echo "Root device: ${root_target}"
    echo "Var device: ${var_target}"
    echo "Boot image: $tmpdir/boot.img"
    echo "Root image: $tmpdir/root.img"

    echo "Reading grubenv configuration..."
    read_grubenv "${grubdir}/grubenv"
    echo "Current boot alternative: ${boot_alternative}"
    echo "Current boot cycle: ${boot_cycle}"

    echo "Writing boot image to ${boot_target}..."
    dd if="$tmpdir/boot.img" of="${boot_target}" bs=1M status=progress
    echo "Boot image written successfully"

    echo "Writing root image to ${root_target}..."
    dd if="$tmpdir/root.img" of="${root_target}" bs=1M status=progress
    echo "Root image written successfully"

    echo "Wiping var partition header on ${var_target}..."
    dd if=/dev/zero of="${var_target}" bs=1M count=16 status=progress
    echo "Var partition header wiped successfully"

    echo "Updating grubenv to prepare for next boot..."
    if [[ "${boot_target}" == *"p7" ]]; then
        boot_alternative="B"
    elif [[ "${boot_target}" == *"p4" ]]; then
        boot_alternative="A"
    else
        echo "ERROR: Invalid boot device partition number"
        exit 1
    fi
    boot_cycle=first_boot
    echo "Setting boot_alternative to ${boot_alternative} and boot_cycle to ${boot_cycle}"
    write_grubenv "${grubdir}/grubenv" "$boot_alternative" "$boot_cycle"
    echo "Grubenv updated successfully"

    echo "Upgrade installation complete"
}

guestos_upgrade_cleanup() {
    echo "Starting cleanup"
    if [ -n "${grubdir}" ] && mountpoint -q "${grubdir}"; then
        umount "${grubdir}"
        echo "Unmounted ${grubdir}"
    fi
    if [ -n "${lodev}" ]; then
        losetup -d "${lodev}"
        echo "Detached loop device ${lodev}"
    fi
    if [ -n "${workdir}" ] && [ -d "${workdir}" ]; then
        rm -rf "${workdir}"
        echo "Removed temporary directory ${workdir}"
    fi
}

main() {
    echo "Starting GuestOS Recovery Upgrader"

    VERSION="$(get_cmdline_var version)"
    SHORT_HASH="$(get_cmdline_var hash)"

    if [ -z "$VERSION" ] || [ -z "$SHORT_HASH" ]; then
        echo "ERROR: Both version and hash parameters are required"
        echo "Usage: version=<commit-hash> hash=<first-6-chars-of-sha256>"
        exit 1
    fi

    echo "Version: $VERSION"
    echo "Short hash: $SHORT_HASH"

    TMPDIR=$(mktemp -d)
    trap 'guestos_upgrade_cleanup; rm -rf "$TMPDIR"' EXIT

    prepare_guestos_upgrade
    download_and_verify_upgrade "$VERSION" "$SHORT_HASH" "$TMPDIR"
    extract_upgrade "$TMPDIR"
    install_upgrade "$TMPDIR"

    echo "Recovery Upgrader completed successfully"

    echo "Launching GuestOS on the new version..."
}

main
