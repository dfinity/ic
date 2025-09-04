#!/bin/bash

# Common grub utilities for IC-OS components

source /opt/ic/bin/logging.sh

# Reads properties "boot_alternative" and "boot_cycle" from the grubenv
# file. The properties are stored as global variables.
#
# Arguments:
# $1 - name of grubenv file
read_grubenv() {
    local GRUBENV_FILE="$1"

    while IFS="=" read -r key value; do
        case "$key" in
            '#'*) ;;
            'boot_alternative' | 'boot_cycle')
                eval "$key=\"$value\""
                ;;
            *) ;;
        esac
    done <"$GRUBENV_FILE"
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
    ) >"${TMP_FILE}" || {
        write_log "Error: Failed to write to temporary file ${TMP_FILE}"
        return 1
    }

    # Truncate to arrive at precisely 1024 bytes
    if ! truncate --size=1024 "${TMP_FILE}"; then
        write_log "Error: Failed to truncate temporary file to 1024 bytes"
        return 1
    fi

    # Create backup of original file if it exists
    if [ -f "${GRUBENV_FILE}" ]; then
        BACKUP_FILE="${GRUBENV_FILE}.backup.$(date +%s)"
        if ! cp "${GRUBENV_FILE}" "${BACKUP_FILE}"; then
            write_log "Error: Failed to create backup of existing grubenv file"
            return 1
        fi
    fi

    # Atomic move: rename temporary file to target file
    if ! mv "${TMP_FILE}" "${GRUBENV_FILE}"; then
        write_log "Error: Failed to atomically move temporary file to ${GRUBENV_FILE}"
        if [ -f "${BACKUP_FILE}" ]; then
            mv "${BACKUP_FILE}" "${GRUBENV_FILE}" 2>/dev/null || true
        fi
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
        return 1
    fi

    write_log "Successfully updated grubenv file: boot_alternative=$boot_alternative, boot_cycle=$boot_cycle"
}
