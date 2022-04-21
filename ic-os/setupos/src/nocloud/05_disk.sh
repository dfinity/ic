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

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    purge_volume_groups
    purge_partitions
    log_end
}

main
