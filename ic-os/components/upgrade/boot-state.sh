#!/bin/bash
set -e

# Common grub utilities for IC-OS components

source /opt/ic/bin/logging.sh

# Read boot_alternative from kernel command line
# Echoes the value of dfinity.system parameter (A or B)
read_boot_alternative_from_kernel_cmdline() {
    local cmdline
    if [ -f /proc/cmdline ]; then
        cmdline=$(cat /proc/cmdline)
        if [[ "$cmdline" =~ dfinity\.system=['\"]?([AB])['\"]? ]]; then
            echo "${BASH_REMATCH[1]}"
            return 0
        fi
    fi
    write_log "ERROR: Could not read dfinity.system from kernel command line"
    return 1
}

# Echoes "boot_alternative" property from the grubenv file.
#
# Arguments:
# $1 - name of grubenv file
read_boot_alternative_from_grubenv() {
    local GRUBENV_FILE="$1"

    while IFS="=" read -r key value; do
        case "$key" in
            '#'*) ;;
            'boot_alternative')
                echo "$value"
                return 0
                ;;
            *) ;;
        esac
    done <"$GRUBENV_FILE"

    write_log "ERROR: Could not read boot_alternative from grubenv file"
    return 1
}

# Echoes "boot_cycle" property from the grubenv file.
#
# Arguments:
# $1 - name of grubenv file
read_boot_cycle_from_grubenv() {
    local GRUBENV_FILE="$1"

    while IFS="=" read -r key value; do
        case "$key" in
            '#'*) ;;
            'boot_cycle')
                echo "$value"
                return 0
                ;;
            *) ;;
        esac
    done <"$GRUBENV_FILE"

    write_log "ERROR: Could not read boot_cycle from grubenv file"
    return 1
}

# Writes "boot_alternative" and "boot_cycle" variables to grubenv file
#
# Arguments:
# $1 - name of grubenv file
# $2 - boot_alternative value
# $3 - boot_cycle value
write_grubenv() {
    local GRUBENV_FILE="$1"
    local boot_alternative="$2"
    local boot_cycle="$3"

    if [ -z "$GRUBENV_FILE" ] || [ -z "$boot_alternative" ] || [ -z "$boot_cycle" ]; then
        write_log "Error: write_grubenv requires 3 parameters: grubenv_file, boot_alternative, boot_cycle"
        return 1
    fi

    # Create temporary file in the same directory as the target for atomic rename
    local GRUBENV_DIR=$(dirname "${GRUBENV_FILE}")
    local TMP_FILE=$(mktemp "${GRUBENV_DIR}/grubenv-XXXXXXXXXXXX")
    local BACKUP_FILE=""

    # Ensure cleanup on exit
    trap 'rm -f "${TMP_FILE}" "${BACKUP_FILE}"' EXIT

    # Write content to temporary file
    (
        echo "# GRUB Environment Block"
        echo boot_alternative="$boot_alternative"
        echo boot_cycle="$boot_cycle"
        # Fill to make sure we will have 1024 bytes
        echo -n "################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################"
    ) >"${TMP_FILE}"

    # Truncate to arrive at precisely 1024 bytes
    truncate --size=1024 "${TMP_FILE}"
    chmod 0644 "${TMP_FILE}"

    # Create backup of original file if it exists
    if [ -f "${GRUBENV_FILE}" ]; then
        BACKUP_FILE="${GRUBENV_FILE}.backup.$(date +%s)"
        cp "${GRUBENV_FILE}" "${BACKUP_FILE}"
    fi

    # Atomic move: rename temporary file to target file
    if ! mv "${TMP_FILE}" "${GRUBENV_FILE}"; then
        write_log "Error: Failed to atomically move temporary file to ${GRUBENV_FILE}"
        return 1
    fi

    # Force sync to ensure the file is written to disk
    local sync_retries=3
    local sync_delay=1
    local sync_success=false

    for ((i = 1; i <= sync_retries; i++)); do
        if sync "${GRUBENV_FILE}"; then
            sync_success=true
            break
        else
            if [ $i -lt $sync_retries ]; then
                write_log "Warning: Sync attempt $i failed, retrying in ${sync_delay}s..."
                sleep $sync_delay
                sync_delay=$((sync_delay * 2))
            fi
        fi
    done

    if [ "$sync_success" = false ]; then
        write_log "Error: Failed to sync grubenv file to disk after $sync_retries attempts"
        # Restore backup if sync failed to ensure system stability
        if [ -f "${BACKUP_FILE}" ]; then
            write_log "Restoring backup grubenv file due to sync failure"
            mv "${BACKUP_FILE}" "${GRUBENV_FILE}" 2>/dev/null || true
        fi
        return 1
    fi

    write_log "Successfully updated grubenv file: boot_alternative=$boot_alternative, boot_cycle=$boot_cycle"
}
