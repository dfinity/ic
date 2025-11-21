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

# Parse command line arguments in the format key=value
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            version=*)
                VERSION="${arg#*=}"
                ;;
            version-hash=*)
                VERSION_HASH="${arg#*=}"
                ;;
            recovery-hash=*)
                RECOVERY_HASH="${arg#*=}"
                ;;
        esac
    done
}

# Helper function to log messages to logger and stdout
log_message() {
    local message="$1"
    # Write to system logger
    logger -t guestos-recovery-upgrader "$message" 2>/dev/null || true
    # Write to stdout so the TUI can capture it
    echo "$message"
}

verify_hash() {
    local file_path="$1"
    local expected_hash="$2"
    local artifact_name="$3"

    log_message "Verifying ${artifact_name} hash..."
    local actual_hash=$(sha256sum "$file_path" | cut -d' ' -f1)
    if [ "$actual_hash" != "$expected_hash" ]; then
        log_message "ERROR: ${artifact_name} hash verification failed"
        log_message "Expected hash: $expected_hash"
        log_message "Got hash: $actual_hash"
        return 1
    fi
    log_message "${artifact_name} hash verification successful"
    return 0
}

download_file() {
    local url_path="$1"
    local output_file="$2"
    local artifact_name="$3"

    local download_successful=false
    for base_url in "${BASE_URLS[@]}"; do
        local url="${base_url}${url_path}"
        log_message "Attempting to download ${artifact_name} from $url..."

        if curl --proto '=https' --location --proto-redir '=https' --tlsv1.2 --silent --show-error --fail -o "$output_file" "$url"; then
            log_message "Download from $base_url completed successfully"
            download_successful=true
            break
        else
            log_message "WARNING: Failed to download from $base_url"
            # Remove partial download file if it exists
            rm -f "$output_file"
        fi
    done

    if [ "$download_successful" = false ]; then
        log_message "ERROR: Failed to download ${artifact_name} from all available URLs"
        return 1
    fi
    return 0
}

retry_operation() {
    local operation_name="$1"
    local operation_function="$2"
    shift 2
    local operation_args=("$@")

    log_message "Starting ${operation_name} with retry logic (max attempts: $MAX_ATTEMPTS, delay: ${RETRY_DELAY}s)..."

    local attempt=1
    while [ $attempt -le $MAX_ATTEMPTS ]; do
        log_message "=== ${operation_name} attempt $attempt/$MAX_ATTEMPTS ==="

        if "$operation_function" "${operation_args[@]}"; then
            log_message "✓ ${operation_name} completed successfully on attempt $attempt"
            return 0
        else
            log_message "✗ ${operation_name} failed on attempt $attempt"

            if [ $attempt -lt $MAX_ATTEMPTS ]; then
                log_message "Waiting ${RETRY_DELAY} seconds before retry..."
                sleep $RETRY_DELAY
            fi
        fi

        ((attempt++))
    done

    log_message "ERROR: Failed to complete ${operation_name} after $MAX_ATTEMPTS attempts"
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
    log_message "Starting guestos upgrade preparation"
    lodev="$(losetup -Pf --show ${GUESTOS_DEVICE})"
    log_message "Set up loop device: $lodev"

    workdir="$(mktemp -d)"
    grubdir="${workdir}/grub"
    mkdir "${grubdir}"
    log_message "Created temporary directories in $workdir"

    mount -o rw,sync "${lodev}p${GRUB_PARTITION_NUM}" "${grubdir}"
    log_message "Mounted grub partition at ${grubdir}"

    boot_alternative="$(grep -oP '^boot_alternative=\K[a-zA-Z]+' "${grubdir}/grubenv")"
    log_message "Current boot alternative: $boot_alternative"

    # Get upgrade partition targets
    read -r boot_target root_target var_target < <(get_upgrade_target_partitions "$lodev" "$boot_alternative")
    log_message "Target boot partition: $boot_target"
    log_message "Target root partition: $root_target"
    log_message "Target var partition: $var_target"
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
    log_message "Extracting upgrade file..."
    zstd -d "$tmpdir/upgrade.tar.zst" -o "$tmpdir/upgrade.tar"
    tar -xf "$tmpdir/upgrade.tar" -C "$tmpdir"
    log_message "Extraction completed"
}

install_upgrade() {
    local tmpdir="$1"
    log_message "Installing upgrade..."

    log_message "=== Recovery Upgrader Mode ==="
    log_message "Grubenv file: ${grubdir}/grubenv"
    log_message "Boot device: ${boot_target}"
    log_message "Root device: ${root_target}"
    log_message "Var device: ${var_target}"
    log_message "Boot image: $tmpdir/boot.img"
    log_message "Root image: $tmpdir/root.img"

    log_message "Reading grubenv configuration..."
    read_grubenv "${grubdir}/grubenv"
    log_message "Current boot alternative: ${boot_alternative}"
    log_message "Current boot cycle: ${boot_cycle}"

    log_message "Writing boot image to ${boot_target}..."
    dd if="$tmpdir/boot.img" of="${boot_target}" bs=1M status=progress
    log_message "Boot image written successfully"

    log_message "Writing root image to ${root_target}..."
    dd if="$tmpdir/root.img" of="${root_target}" bs=1M status=progress
    log_message "Root image written successfully"

    log_message "Wiping var partition header on ${var_target}..."
    dd if=/dev/zero of="${var_target}" bs=1M count=16 status=progress
    log_message "Var partition header wiped successfully"

    log_message "Updating grubenv to prepare for next boot..."
    if [[ "${boot_target}" == *"p7" ]]; then
        boot_alternative="B"
    elif [[ "${boot_target}" == *"p4" ]]; then
        boot_alternative="A"
    else
        log_message "ERROR: Invalid boot device partition number"
        exit 1
    fi
    boot_cycle=first_boot
    log_message "Setting boot_alternative to ${boot_alternative} and boot_cycle to ${boot_cycle}"
    write_grubenv "${grubdir}/grubenv" "$boot_alternative" "$boot_cycle"
    log_message "Grubenv updated successfully"

    log_message "Upgrade installation complete"
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
    log_message "Starting cleanup"
    if [ -n "${grubdir}" ] && mountpoint -q "${grubdir}"; then
        umount "${grubdir}"
        log_message "Unmounted ${grubdir}"
    fi
    if [ -n "${lodev}" ]; then
        losetup -d "${lodev}"
        log_message "Detached loop device ${lodev}"
    fi
    if [ -n "${workdir}" ] && [ -d "${workdir}" ]; then
        rm -rf "${workdir}"
        log_message "Removed temporary directory ${workdir}"
    fi
}

main() {
    log_message "Starting GuestOS Recovery Upgrader"

    VERSION=""
    VERSION_HASH=""
    RECOVERY_HASH=""
    parse_args "$@"

    log_message "Parsed VERSION='$VERSION' VERSION_HASH='$VERSION_HASH' RECOVERY_HASH='$RECOVERY_HASH'"

    if [ -z "$VERSION" ] || [ -z "$VERSION_HASH" ]; then
        log_message "ERROR: version and version-hash parameters are required"
        log_message "Usage: version=<commit-hash> version-hash=<sha256> [recovery-hash=<sha256>]"
        # Sleep 15 seconds then repeat error message to ensure visibility after console initialization wipe
        sleep 15
        log_message "ERROR: version and version-hash parameters are required"
        log_message "Usage: version=<commit-hash> version-hash=<sha256> [recovery-hash=<sha256>]"
        exit 1
    fi

    log_message "Version: $VERSION"
    log_message "Version hash: $VERSION_HASH"
    if [ -n "$RECOVERY_HASH" ]; then
        log_message "Recovery hash: $RECOVERY_HASH"
    else
        log_message "Recovery hash not provided (optional for testing)"
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
        log_message "Skipping recovery artifact download and verification (recovery-hash not provided)"
    fi

    extract_upgrade "$TMPDIR"

    log_message "Stopping guestos.service for manual upgrade"
    systemctl stop guestos.service
    log_message "GuestOS service stopped"

    install_upgrade "$TMPDIR"

    log_message "Recovery Upgrader completed successfully"

    log_message "Launching GuestOS on the new version..."

    if [ -n "$RECOVERY_HASH" ]; then
        log_message "Writing recovery hash to file"
        RECOVERY_FILE="/run/config/guestos_recovery_hash"
        mkdir -p "$(dirname "$RECOVERY_FILE")"
        echo "$RECOVERY_HASH" >"$RECOVERY_FILE"
        log_message "Recovery hash written to $RECOVERY_FILE"
    fi

    log_message "Restarting guestos service after manual upgrade"
    systemctl start guestos.service
    log_message "GuestOS service restarted successfully"
}

main "$@"
