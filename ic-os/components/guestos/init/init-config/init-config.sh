#!/bin/bash

# Initialize configuration in /run/config from config partition.

set -eo pipefail

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

function mount_config_device() {
    MAX_TRIES=10
    CONFIG_DEVICE="/dev/disk/by-label/CONFIG"

    while [ $MAX_TRIES -gt 0 ]; do
        echo "Waiting for a ${CONFIG_DEVICE} device for mounting"

        # Check if device exists & is a symlink to the real one
        if [ -L "${CONFIG_DEVICE}" ]; then
            echo "Found ${CONFIG_DEVICE} device, mounting at /mnt/config"

            # Ensure that the config device is vfat. If we ever change to another filesystem type, we should ensure
            # that it only contains regular files and directories (not symlinks, devices, etc.).
            if mount -t vfat -o ro ${CONFIG_DEVICE} /mnt/config; then
                echo "Successfully mounted ${CONFIG_DEVICE} device at /mnt/config"
                return 0
            else
                echo "Failed to mount ${CONFIG_DEVICE} device at /mnt/config"
            fi
        fi

        MAX_TRIES=$(($MAX_TRIES - 1))
        if [ $MAX_TRIES == 0 ]; then
            echo "No ${CONFIG_DEVICE} device found for mounting"
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

mkdir /run/config
mkdir /run/config/bootstrap

# Check if ic-bootstrap.tar exists (backward compatibility with older HostOS versions)
# TODO(NODE-1821): Remove this check once all nodes have HostOS that supports tarless configuration.
if [ -f /mnt/config/ic-bootstrap.tar ]; then
    echo "Found ic-bootstrap.tar, using legacy tar-based configuration"

    # Verify that ic-bootstrap.tar contains only regular files (-) and directories (d)
    if tar -tvf /mnt/config/ic-bootstrap.tar | cut -c 1 | grep -E -q '[^-d]'; then
        echo "ic-bootstrap.tar contains non-regular files, aborting"
        exit 1
    fi

    tar xf /mnt/config/ic-bootstrap.tar -C /run/config/bootstrap
else
    echo "Using direct file-based configuration"
    cp -r /mnt/config/* /run/config/bootstrap/
fi

if [ -f /run/config/bootstrap/config.json ]; then
    cp /run/config/bootstrap/config.json /run/config/config.json
    chown ic-replica:nogroup /run/config/config.json
else
    echo "config.json not found in config partition"
    exit 1
fi

# Create file under /run/config/guest_vm_type, this can be used to add ConditionPathExists conditions to systemd units
guest_vm_type="$(jq -r ".guest_vm_type" /run/config/config.json)"
if [[ "$guest_vm_type" = null ]]; then
    guest_vm_type=default
fi
mkdir -p "/run/config/guest_vm_type"
touch "/run/config/guest_vm_type/$guest_vm_type"
