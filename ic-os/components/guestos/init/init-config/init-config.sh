#!/bin/bash

# Initialize configuration in /run/config from bootstrap package.

set -eo pipefail

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

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
            if [ "$IS_REMOVABLE" == 1 ] || [ "$CONFIG_SERIAL" != "" ] || [ "$FS_LABEL" == "CONFIG" ]; then
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
                if blockdev "$TGT" 2>/dev/null; then
                    echo "$TGT"
                fi
            fi
        fi
    done
}

function mount_config_device() {
    MAX_TRIES=10

    while [ $MAX_TRIES -gt 0 ]; do
        echo "Locating CONFIG device for mounting"
        config_device="$(find_config_devices)"

        if [ "$config_device" != "" ]; then
            echo "Found CONFIG device at $config_device, creating mount at /mnt/config"

            if mount -t vfat -o ro "$config_device" /mnt/config; then
                echo "Successfully mounted CONFIG device at /mnt/config"
                return 0
            else
                echo "Failed to mount CONFIG device at $config_device"
            fi
        fi

        MAX_TRIES=$(($MAX_TRIES - 1))
        if [ $MAX_TRIES == 0 ]; then
            echo "No CONFIG device found for mounting"
            return 1
        else
            echo "Retrying to find CONFIG device"
            sleep 1
        fi
    done
}

if ! mount_config_device; then
    exit 1
fi

trap "umount /mnt/config" EXIT

# Verify that ic-bootstrap.tar contains only regular files (-) and directories (d)
if tar -tvf /mnt/config/ic-bootstrap.tar | cut -c 1 | grep -E -q '[^-d]'; then
    echo "ic-bootstrap.tar contains non-regular files, aborting"
    exit 1
fi

mkdir -p /run/config/bootstrap
tar xf /mnt/config/ic-bootstrap.tar -C /run/config/bootstrap
cp /run/config/bootstrap/config.json /run/config/config.json
chown ic-replica:nogroup /run/config/config.json
/opt/ic/bin/config populate-nns-public-key

# Create file under /run/config/guest_vm_type, this can be used to add ConditionPathExists conditions to systemd units
guest_vm_type="$(jq -r ".guest_vm_type" /run/config/config.json)"
if [[ "$guest_vm_type" = null ]]; then
    guest_vm_type=default
fi
mkdir -p "/run/config/guest_vm_type"
touch "/run/config/guest_vm_type/$guest_vm_type"
