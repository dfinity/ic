#!/bin/bash

# Mount the configuration device at /mnt/config
# This script handles the mounting part that was previously in init-config.sh

set -eo pipefail

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename $0)[$$]"

# List all block devices that could potentially contain the ic-bootstrap.tar configuration,
# i.e. "removable" devices, devices with the serial "config"
# or devices containing a filesystem with the label "CONFIG".
function find_config_devices() {
    for DEV in $(ls -C /sys/class/block); do
        echo "Consider device $DEV" >&2
        if [ -e /sys/class/block/"${DEV}"/removable ]; then
            # In production, a removable device is used to pass configuration
            # into the VM.
            # In some test environments where this is not available, the
            # configuration device is identified by the serial "config".
            local IS_REMOVABLE=$(cat /sys/class/block/"${DEV}"/removable)
            local CONFIG_SERIAL=$(udevadm info --name=/dev/"${DEV}" | grep "ID_SCSI_SERIAL=config" || true)
            local FS_LABEL=$(lsblk --fs --noheadings --output LABEL /dev/"${DEV}" 2>/dev/null || true)
            if [ "${IS_REMOVABLE}" == 1 ] || [ "${CONFIG_SERIAL}" != "" ] || [ "${FS_LABEL}" == "CONFIG" ]; then
                # If this is a partitioned device (and it usually is), then
                # the first partition is of relevance.
                # return first partition for use instead.
                if [ -e /sys/class/block/"${DEV}1" ]; then
                    local TGT="/dev/${DEV}1"
                elif [ -e /sys/class/block/"${DEV}p1" ]; then
                    local TGT="/dev/${DEV}p1"
                else
                    local TGT="/dev/${DEV}"
                fi
                # Sanity check whether device is usable (it could be a
                # CD drive with no medium in)
                if blockdev "${TGT}" 2>/dev/null; then
                    echo "$TGT"
                fi
            fi
        fi
    done
}

MAX_TRIES=10

while [ "${MAX_TRIES}" -gt 0 ]; do
    echo "Locating CONFIG device for mounting"
    DEV="$(find_config_devices)"

    # Check whether we were provided with a CONFIG device -- on "real"
    # VM deployments this will be the method used to inject bootstrap information
    # into the system.
    if [ "${DEV}" != "" ]; then
        echo "Found CONFIG device at ${DEV}, creating mount at /mnt/config"
        mkdir -p /mnt/config

        if mount -t vfat -o ro "${DEV}" /mnt/config; then
            echo "Successfully mounted CONFIG device at /mnt/config"
            exit 0
        else
            echo "Failed to mount CONFIG device at ${DEV}"
            rmdir /mnt/config 2>/dev/null || true
        fi
    else
        echo "No CONFIG device found"
    fi

    MAX_TRIES=$(("${MAX_TRIES}" - 1))
    if [ "${MAX_TRIES}" == 0 ]; then
        echo "No CONFIG device found for mounting"
        exit 1
    else
        echo "Retrying to find CONFIG device"
        sleep 1
    fi
done
