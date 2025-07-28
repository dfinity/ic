#!/bin/bash

# Common grub utilities for IC-OS components

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
        echo "Error: write_grubenv requires 3 parameters: grubenv_file, boot_alternative, boot_cycle" >&2
        return 1
    fi

    TMP_FILE=$(mktemp /tmp/grubenv-XXXXXXXXXXXX)
    (
        echo "# GRUB Environment Block"
        echo boot_alternative="$boot_alternative"
        echo boot_cycle="$boot_cycle"
        # Fill to make sure we will have 1024 bytes
        echo -n "################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################"
    ) >"${TMP_FILE}"
    # Truncate to arrive at precisely 1024 bytes
    truncate --size=1024 "${TMP_FILE}"
    cat "${TMP_FILE}" >"${GRUBENV_FILE}"
    rm "${TMP_FILE}"
}
