#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

function purge_partitions() {
    echo "* Purging partitions..."

    # Destroy guest partitions (for redeployments)
    vgscan --mknodes
    loop_device=$(losetup -P -f /dev/mapper/hostlvm-guestos --show)
    if [ "${loop_device}" != "" ]; then
        echo "Loop device detected: ${loop_device}. Wiping partitions."
        wipefs --all --force "${loop_device}"*
        if [ "${?}" -ne 0 ]; then
            echo "WARNING: Unable to purge GuestOS partitions on ${loop_device}"
        fi
        losetup -d "${loop_device}"
    else
        echo "Unable to detect GuestOS loop device (may not exist)"
    fi

    # Destroy host partitions (for redeployments)
    wipefs --all --force "/dev/mapper/hostlvm"*
    if [ "${?}" -ne 0 ]; then
        echo "Unable to purge HostOS partitions (may not exist)"
    fi
    vgremove --force hostlvm

    # Destroy master boot record and partition table
    large_drives=($(get_large_drives))
    for drive in "${large_drives[@]}"; do
        echo "Wiping partitions on drive: /dev/${drive}."

        # Remove any LVM metadata
        pvremove --force "/dev/${drive}"* 2>/dev/null || true

        # Wipe the partition table and filesystem signatures
        wipefs --all --force "/dev/${drive}"*
        if [ "${?}" -ne 0 ]; then
            log_and_halt_installation_on_error 1 "Failed to wipe partitions on /dev/${drive}"
        fi

        # Verify the wipe was successful
        if [ -e "/dev/${drive}1" ] || [ -e "/dev/${drive}2" ] || [ -e "/dev/${drive}3" ]; then
            log_and_halt_installation_on_error 1 "Partitions still exist after wipe on /dev/${drive}"
        fi
    done

    # Remove all device mapper mappings
    dmsetup remove_all 2>/dev/null || true
}

function setup_storage() {
    echo "Starting storage setup..."

    system_drive=$(find_first_drive)
    # Create PVs on each additional drive
    large_drives=($(get_large_drives))
    for drive in "${large_drives[@]}"; do
        # Avoid creating PV on system drive
        if [ "/dev/${drive}" == "/dev/${system_drive}" ]; then
            continue
        fi

        test -b "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Drive '/dev/${drive}' not found. Are all drives correctly installed?"

        echo "Creating physical volume on /dev/${drive}."
        pvcreate "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Unable to setup PV on drive '/dev/${drive}'."
        echo "Physical volume created on /dev/${drive}."
    done
}

# Establish run order
main() {
    log_start "$(basename $0)"
    purge_partitions
    setup_storage
    log_end "$(basename $0)"
}

main
