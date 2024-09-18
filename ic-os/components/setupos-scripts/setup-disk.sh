#!/usr/bin/env bash

set -o nounset
set -o pipefail

source /opt/ic/bin/functions.sh

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function purge_partitions() {
    echo "* Purging partitions..."

    # Destroy guest partitions
    vgscan --mknodes
    loop_device=$(losetup -P -f /dev/mapper/hostlvm-guestos --show)

    if [ "${loop_device}" != "" ]; then
        wipefs --all --force "${loop_device}"*
        if [ "${?}" -ne 0 ]; then
            echo "Unable to purge GuestOS partitions"
        fi
        losetup -d "${loop_device}"
    fi

    # Destroy host partitions
    wipefs --all --force "/dev/mapper/hostlvm"*
    if [ "${?}" -ne 0 ]; then
        echo "Unable to purge HostOS partitions"
    fi
    vgremove --force hostlvm

    # Destroy master boot record and partition table
    large_drives=($(get_large_drives))

    for drive in $(echo ${large_drives[@]}); do
        wipefs --all --force "/dev/${drive}"*
        if [ "${?}" -ne 0 ]; then
            echo "Unable to purge partitions on drive: /dev/${drive}"
        fi
    done
}

function setup_storage() {
    system_drive=$(find_first_drive)

    # Create PVs on each additional drive
    large_drives=($(get_large_drives))
    for drive in $(echo ${large_drives[@]}); do
        # Avoid creating PV on system drive
        if [ "/dev/${drive}" == "/dev/${system_drive}" ]; then
            continue
        fi

        test -b "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Drive '/dev/${drive}' not found. Are all drives correctly installed?"

        pvcreate "/dev/${drive}"
        log_and_halt_installation_on_error "${?}" "Unable to setup PV on drive '/dev/${drive}'."
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
