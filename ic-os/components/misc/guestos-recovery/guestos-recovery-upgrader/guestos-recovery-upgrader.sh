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

# Global parameters
MODE="" # must be provided: run | prep | install
STAGE_DIR="/run/guestos-recovery/stage"
METADATA_FILE="${STAGE_DIR}/prep-info"
PRESERVE_STAGE_DIR=false

VERSION=""
VERSION_HASH_FULL=""
RECOVERY_HASH_PREFIX=""
RECOVERY_HASH_FULL=""

source /opt/ic/bin/grub.sh

# Parse command line arguments in the format key=value
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            version=*)
                VERSION="${arg#*=}"
                ;;
            recovery-hash-prefix=*)
                RECOVERY_HASH_PREFIX="${arg#*=}"
                ;;
            mode=*)
                MODE="${arg#*=}"
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

compute_sha256() {
    local file_path="$1"
    sha256sum "$file_path" | cut -d' ' -f1
}

write_prep_metadata() {
    cat >"${METADATA_FILE}" <<EOF
VERSION=${VERSION}
RECOVERY_HASH_PREFIX=${RECOVERY_HASH_PREFIX}
VERSION_HASH_FULL=${VERSION_HASH_FULL}
RECOVERY_HASH_FULL=${RECOVERY_HASH_FULL}
EOF
    chmod 644 "${METADATA_FILE}" || true
}

load_prep_metadata() {
    if [ ! -f "${METADATA_FILE}" ]; then
        log_message "ERROR: Prep metadata not found at ${METADATA_FILE}"
        return 1
    fi

    while IFS='=' read -r key value; do
        case "$key" in
            VERSION) VERSION="$value" ;;
            RECOVERY_HASH_PREFIX) RECOVERY_HASH_PREFIX="$value" ;;
            VERSION_HASH_FULL) VERSION_HASH_FULL="$value" ;;
            RECOVERY_HASH_FULL) RECOVERY_HASH_FULL="$value" ;;
        esac
    done <"${METADATA_FILE}"
}

print_success_banner() {
    local green="\033[32m"
    local bold="\033[1m"
    local reset="\033[0m"
    echo
    echo -e "${green}${bold}========================================================"${reset}
    echo -e "${green}${bold}SUCCESS: Recovery completed successfully!${reset}"
    echo -e "${green}${bold}========================================================"${reset}
    echo
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

download_upgrade_and_hash() {
    local version="$1"
    local tmpdir="$2"

    local url_path="/ic/${version}/guest-os/update-img-recovery/update-img.tar.zst"
    local output_file="$tmpdir/upgrade.tar.zst"

    if ! download_file "$url_path" "$output_file" "upgrade file"; then
        return 1
    fi

    VERSION_HASH_FULL=$(compute_sha256 "$output_file")
    log_message "Calculated upgrade image hash: $VERSION_HASH_FULL"
    return 0
}

extract_upgrade() {
    local tmpdir="$1"
    local extract_dir="$2"
    log_message "Extracting upgrade file..."

    # Extract to /tmp to avoid running out of space in /run (tmpfs)
    log_message "Using temporary extraction directory: $extract_dir"
    zstd -d "$tmpdir/upgrade.tar.zst" -o "$extract_dir/upgrade.tar"
    tar -xf "$extract_dir/upgrade.tar" -C "$extract_dir"
    log_message "Extraction completed. Files available in $extract_dir"
}

install_upgrade() {
    local tmpdir="$1"
    local extract_dir="$2"
    log_message "Installing upgrade..."

    log_message "=== Recovery Upgrader Mode ==="
    log_message "Grubenv file: ${grubdir}/grubenv"
    log_message "Boot device: ${boot_target}"
    log_message "Root device: ${root_target}"
    log_message "Var device: ${var_target}"
    log_message "Boot image: $extract_dir/boot.img"
    log_message "Root image: $extract_dir/root.img"

    log_message "Reading grubenv configuration..."
    read_grubenv "${grubdir}/grubenv"
    log_message "Current boot alternative: ${boot_alternative}"
    log_message "Current boot cycle: ${boot_cycle}"

    log_message "Writing boot image to ${boot_target}..."
    dd if="$extract_dir/boot.img" of="${boot_target}" bs=1M status=progress
    log_message "Boot image written successfully"

    log_message "Writing root image to ${root_target}..."
    dd if="$extract_dir/root.img" of="${root_target}" bs=1M status=progress
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

download_recovery_and_hash() {
    local recovery_hash_prefix="$1"
    local tmpdir="$2"

    # local url_path="/recovery/${recovery_hash_prefix}/recovery.tar.zst"
    #LEAVE THIS FOR TESTING:
    local url_path="/recovery/7ff9e45010f7a343712dc05bbf67fba26971c2b48df8cfbee09cee1895d3e907/recovery.tar.zst"
    local output_file="$tmpdir/recovery.tar.zst"

    if ! download_file "$url_path" "$output_file" "recovery artifact"; then
        return 1
    fi

    RECOVERY_HASH_FULL=$(compute_sha256 "$output_file")
    log_message "Calculated recovery artifact hash: $RECOVERY_HASH_FULL"

    if [[ "$RECOVERY_HASH_FULL" != "${recovery_hash_prefix}"* ]]; then
        log_message "ERROR: Calculated recovery hash does not start with provided prefix (${recovery_hash_prefix})"
        return 1
    fi
    return 0
}

prep_phase() {
    log_message "Starting artifact preparation phase"
    log_message "Staging directory: ${STAGE_DIR}"
    rm -rf "${STAGE_DIR}"
    mkdir -p "${STAGE_DIR}"

    if ! retry_operation "recovery-GuestOS upgrade image download and hashing" download_upgrade_and_hash "$VERSION" "$STAGE_DIR"; then
        return 1
    fi

    if ! retry_operation "recovery artifact download and hashing" download_recovery_and_hash "$RECOVERY_HASH_PREFIX" "$STAGE_DIR"; then
        return 1
    fi

    write_prep_metadata

    log_message "Prep phase complete. Calculated hashes:"
    log_message "  VERSION-HASH: ${VERSION_HASH_FULL}"
    log_message "  RECOVERY-HASH: ${RECOVERY_HASH_FULL}"
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
    if [ -n "${extract_dir}" ] && [ -d "${extract_dir}" ]; then
        rm -rf "${extract_dir}"
        log_message "Removed extraction directory ${extract_dir}"
    fi
    if [ "$PRESERVE_STAGE_DIR" != "true" ] && [ -n "${STAGE_DIR}" ] && [ -d "${STAGE_DIR}" ]; then
        rm -rf "${STAGE_DIR}"
        log_message "Removed staging directory ${STAGE_DIR}"
    elif [ -n "${STAGE_DIR}" ]; then
        log_message "Staging directory preserved at ${STAGE_DIR}"
    fi
}

main() {
    log_message "Starting GuestOS Recovery Upgrader"

    parse_args "$@"

    log_message "Parsed VERSION='$VERSION' MODE='$MODE' RECOVERY_HASH_PREFIX='$RECOVERY_HASH_PREFIX'"

    if [[ -z "$MODE" || ("$MODE" != "run" && "$MODE" != "prep" && "$MODE" != "install") ]]; then
        log_message "ERROR: mode must be one of run|prep|install"
        exit 1
    fi

    if [ "$MODE" != "install" ] && { [ -z "$VERSION" ] || [ -z "$RECOVERY_HASH_PREFIX" ]; }; then
        log_message "ERROR: version and recovery-hash-prefix parameters are required"
        log_message "Usage: mode=<run|prep|install> version=<commit-hash> recovery-hash-prefix=<prefix-hex>"
        exit 1
    fi

    mkdir -p "$(dirname "${STAGE_DIR}")"

    extract_dir=""
    if [ "$MODE" != "prep" ]; then
        extract_dir="$(mktemp -d)"
    fi

    trap 'guestos_upgrade_cleanup' EXIT

    if [ "$MODE" != "install" ]; then
        if ! prep_phase; then
            exit 1
        fi
        if [ "$MODE" = "prep" ]; then
            PRESERVE_STAGE_DIR=true
            log_message "Prep completed. To install, rerun with: mode=install"
            return 0
        fi
    else
        if ! load_prep_metadata; then
            exit 1
        fi
        log_message "Loaded prep metadata from ${STAGE_DIR}"
        log_message "  VERSION: ${VERSION}"
        log_message "  VERSION-HASH: ${VERSION_HASH_FULL}"
        log_message "  RECOVERY-HASH (prefix): ${RECOVERY_HASH_PREFIX}"
        log_message "  RECOVERY-HASH (full): ${RECOVERY_HASH_FULL}"
    fi

    if [ ! -f "${STAGE_DIR}/upgrade.tar.zst" ] || [ ! -f "${STAGE_DIR}/recovery.tar.zst" ]; then
        log_message "ERROR: Staging directory is missing required artifacts (${STAGE_DIR})"
        exit 1
    fi

    prepare_guestos_upgrade

    extract_upgrade "$STAGE_DIR" "$extract_dir"

    log_message "Stopping guestos.service for manual upgrade"
    systemctl stop guestos.service
    log_message "GuestOS service stopped"

    install_upgrade "$STAGE_DIR" "$extract_dir"

    log_message "Recovery Upgrader completed successfully"

    log_message "Launching GuestOS on the new version..."

    log_message "Writing recovery hash to file"
    RECOVERY_FILE="/run/config/guestos_recovery_hash"
    mkdir -p "$(dirname "$RECOVERY_FILE")"
    echo "$RECOVERY_HASH_FULL" >"$RECOVERY_FILE"
    log_message "Recovery hash written to $RECOVERY_FILE"

    log_message "Restarting guestos.service after manual upgrade installation"
    systemctl start guestos.service
    log_message "GuestOS service restarted successfully"

    # Log success banner in so that it is visible in manual recovery fallback method
    print_success_banner
}

main "$@"
