#!/usr/bin/env bash

set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function purge_volume_groups() {
    echo "* Purging volume groups..."

    vgcount=$(find /dev/mapper/ -type l | wc -l)
    if [ ${vgcount} -gt 0 ]; then
        vgs=$(find /dev/mapper/ -type l)
        for vg in ${vgs}; do
            echo ${vg}
            dmsetup remove --force ${vg} >/dev/null 2>&1
            log_and_reboot_on_error "${?}" "Unable to purge volume groups."
        done
    fi
}

function purge_partitions() {
    echo "* Purging partitions..."

    # Destroy master boot record and partition table
    nvme_drives=($(find /dev/ -type b -iname "nvme*n1" | sort))
    vda_drives=($(find /dev/ -type b -iname "vd*" | sort))

    if [ ! -z "${nvme_drives}" ]; then
        for drive in $(echo ${nvme_drives[@]}); do
            wipefs --all --force ${drive}
            log_and_reboot_on_error "${?}" "Unable to purge partitions on drive: ${drive}"
        done
    elif [ ! -z "${vda_drives}" ]; then
        for drive in $(echo ${vda_drives[@]}); do
            wipefs --all --force ${drive}
            log_and_reboot_on_error "${?}" "Unable to purge partitions on drive: ${drive}"
        done
    else
        log_and_reboot_on_error "1" "Unable to locate suitable system drive."
    fi
}

function setup_storage() {
    # Create PVs on each additional drive, at the same time, check that we have the required amount
    skew=$(detect_skew)
    if [ "${skew}" == "dell" ]; then
        drives=9
    elif [ "${skew}" == "supermicro" ]; then
        drives=4
    else
        log_and_reboot_on_error "1" "Unknown machine skew."
    fi

    for drive in $(seq 1 ${drives}); do
        test -b "/dev/nvme${drive}n1"
        log_and_reboot_on_error "${?}" "Drive '/dev/nvme${drive}n1' not found. Are all drives correctly installed?"

        pvcreate "/dev/nvme${drive}n1"
        log_and_reboot_on_error "${?}" "Unable to setup PV on drive '/dev/nvme${drive}n1'."
    done
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    purge_volume_groups
    purge_partitions
    setup_storage
    log_end "$(basename $0)"
}

main
