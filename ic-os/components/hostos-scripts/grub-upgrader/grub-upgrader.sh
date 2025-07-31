#!/bin/bash
set -euo pipefail

SRC="/boot/grub.cfg"
DST="/boot/grub/grub.cfg"

read_boot_state() {
    local grubenv_file="/boot/grub/grubenv"

    if [ ! -f "${grubenv_file}" ]; then
        echo "Grubenv file ${grubenv_file} not found. Cannot determine boot cycle state." >&2
        return 1
    fi

    while IFS="=" read -r key value; do
        if [ "$key" = "boot_cycle" ]; then
            echo "$value"
            return 0
        fi
    done <"${grubenv_file}"

    return 1
}

wait_for_stable_boot() {
    local timeout=600
    local start_time=$(date +%s)
    local current_time
    local elapsed_time

    echo "Checking boot cycle stability..."

    while true; do
        local boot_state
        if boot_state="$(read_boot_state)"; then
            if [ "${boot_state}" == "stable" ]; then
                echo "System is stable (boot_cycle=stable). Proceeding with grub update."
                return 0
            else
                echo "System not stable (boot_cycle=${boot_state}). Waiting..."
            fi
        else
            echo "Failed to read boot state from grubenv. Waiting..."
        fi

        current_time=$(date +%s)
        elapsed_time=$((current_time - start_time))

        if [ $elapsed_time -ge $timeout ]; then
            echo "Timeout reached ($timeout seconds). System did not become stable. Exiting without updating grub." >&2
            exit 1
        fi

        sleep 30
    done
}

if [ ! -f "${SRC}" ]; then
    echo "Source grub configuration not found at ${SRC}. Exiting." >&2
    exit 1
fi

if [ ! -d "$(dirname "${DST}")" ]; then
    echo "Destination directory $(dirname "${DST}") does not exist. Exiting." >&2
    exit 1
fi

# Check if destination file exists and compare with source
if [ -f "${DST}" ] && cmp -s "${SRC}" "${DST}"; then
    echo "Source and destination grub configurations are identical. No action needed."
    exit 0
fi

echo "Waiting for system to become stable (meaning the last OS upgrade was confirmed) before applying grub update..."
wait_for_stable_boot

echo "Source and destination grub configurations differ. Copying ${SRC} to ${DST}..."
cp "${SRC}" "${DST}"

echo "Grub configuration updated successfully. Rebooting..."
reboot
