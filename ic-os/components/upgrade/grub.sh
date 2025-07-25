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
