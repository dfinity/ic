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

MAX_ATTEMPTS=10
RETRY_DELAY=5

GUESTOS_DEVICE="/dev/hostlvm/guestos"

BASE_URLS=(
    "https://download.dfinity.systems"
    "https://download.dfinity.network"
)

source /opt/ic/bin/grub.sh

# Helper function to extract a value from /proc/cmdline
get_cmdline_var() {
    local var="$1"
    grep -oP "${var}=[^ ]*" /proc/cmdline | head -n1 | cut -d= -f2-
}

verify_hash() {
    local file_path="$1"
    local expected_hash="$2"
    local artifact_name="$3"

    echo "Verifying ${artifact_name} hash..."
    local actual_hash=$(sha256sum "$file_path" | cut -d' ' -f1)
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "ERROR: ${artifact_name} hash verification failed"
        echo "Expected hash: $expected_hash"
        echo "Got hash: $actual_hash"
        return 1
    fi
    echo "${artifact_name} hash verification successful"
    return 0
}

download_file() {
    local url_path="$1"
    local output_file="$2"
    local artifact_name="$3"

    local download_successful=false
    for base_url in "${BASE_URLS[@]}"; do
        local url="${base_url}${url_path}"
        echo "Attempting to download ${artifact_name} from $url..."

        if curl --proto '=https' --location --proto-redir '=https' --tlsv1.2 --silent --show-error --fail -o "$output_file" "$url"; then
            echo "Download from $base_url completed successfully"
            download_successful=true
            break
        else
            echo "WARNING: Failed to download from $base_url"
            # Remove partial download file if it exists
            rm -f "$output_file"
        fi
    done

    if [ "$download_successful" = false ]; then
        echo "ERROR: Failed to download ${artifact_name} from all available URLs"
        return 1
    fi
    return 0
}

retry_operation() {
    local operation_name="$1"
    local operation_function="$2"
    shift 2
    local operation_args=("$@")

    echo "Starting ${operation_name} with retry logic (max attempts: $MAX_ATTEMPTS, delay: ${RETRY_DELAY}s)..."

    local attempt=1
    while [ $attempt -le $MAX_ATTEMPTS ]; do
        echo "=== ${operation_name} attempt $attempt/$MAX_ATTEMPTS ==="

        if "$operation_function" "${operation_args[@]}"; then
            echo "✓ ${operation_name} completed successfully on attempt $attempt"
            return 0
        else
            echo "✗ ${operation_name} failed on attempt $attempt"

            if [ $attempt -lt $MAX_ATTEMPTS ]; then
                echo "Waiting ${RETRY_DELAY} seconds before retry..."
                sleep $RETRY_DELAY
            fi
        fi

        ((attempt++))
    done

    echo "ERROR: Failed to complete ${operation_name} after $MAX_ATTEMPTS attempts"
    return 1
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
    grubdir="${workdir}/grub"
    mkdir "${grubdir}"
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
    local expected_hash="$2"
    local tmpdir="$3"

    local url_path="/ic/${version}/guest-os/update-img-recovery/update-img.tar.zst"
    local output_file="$tmpdir/upgrade.tar.zst"

    if ! download_file "$url_path" "$output_file" "upgrade file"; then
        return 1
    fi

    if ! verify_hash "$output_file" "$expected_hash" "upgrade image"; then
        return 1
    fi

    return 0
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

download_and_verify_recovery() {
    local expected_recovery_hash="$1"
    local tmpdir="$2"

    local url_path="/recovery/${expected_recovery_hash}/recovery.tar.zst"
    local output_file="$tmpdir/recovery.tar.zst"

    if ! download_file "$url_path" "$output_file" "recovery artifact"; then
        return 1
    fi

    if ! verify_hash "$output_file" "$expected_recovery_hash" "recovery artifact"; then
        return 1
    fi

    return 0
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
    VERSION_HASH="$(get_cmdline_var version-hash)"
    RECOVERY_HASH="$(get_cmdline_var recovery-hash)"

    if [ -z "$VERSION" ] || [ -z "$VERSION_HASH" ]; then
        echo "ERROR: version and version-hash parameters are required"
        echo "Usage: version=<commit-hash> version-hash=<sha256> [recovery-hash=<sha256>]"
        exit 1
    fi

    echo "Version: $VERSION"
    echo "Version hash: $VERSION_HASH"
    if [ -n "$RECOVERY_HASH" ]; then
        echo "Recovery hash: $RECOVERY_HASH"
    else
        echo "Recovery hash not provided (optional)"
    fi

    TMPDIR=$(mktemp -d)
    trap 'guestos_upgrade_cleanup; rm -rf "$TMPDIR"' EXIT

    prepare_guestos_upgrade

    if ! retry_operation "recovery-GuestOS upgrade image download and verification" download_and_verify_upgrade "$VERSION" "$VERSION_HASH" "$TMPDIR"; then
        exit 1
    fi

    if [ -n "$RECOVERY_HASH" ]; then
        if ! retry_operation "recovery artifact download and verification" download_and_verify_recovery "$RECOVERY_HASH" "$TMPDIR"; then
            exit 1
        fi
    else
        echo "Skipping recovery artifact download and verification (recovery-hash not provided)"
    fi

    extract_upgrade "$TMPDIR"
    install_upgrade "$TMPDIR"

    echo "Recovery Upgrader completed successfully"

    echo "Launching GuestOS on the new version..."
}

main
