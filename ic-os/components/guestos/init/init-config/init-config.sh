#!/bin/bash

# Initialize configuration in /run/config from config partition.

set -eo pipefail

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

function mount_config_device() {
    CONFIG_DEVICE="/dev/disk/by-label/CONFIG"

    # Proactively trigger udev to re-discover block devices and wait for all
    # events (including /dev/disk/by-label/ symlink creation) to be processed.
    # This is more reliable than passive polling with sleep because it forces
    # the kernel to re-emit device events and deterministically waits for udev
    # to finish processing them.
    echo "Triggering udev to discover block devices"
    udevadm trigger --subsystem-match=block --action=add
    udevadm settle --timeout=10 --exit-if-exists="${CONFIG_DEVICE}"

    echo "Checking for ${CONFIG_DEVICE} device"

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

    echo "No ${CONFIG_DEVICE} device found for mounting"
    return 1
}

# Try config disk first, then run Cloud provisioning if that fails
if ! mount_config_device; then
    echo "Config disk not found, trying cloud provisioning"

    # Since root is read-only - mount a tmpfs at /mnt/config to be able to write a config.json there
    mount -t tmpfs config /mnt/config

    if ! /opt/ic/bin/guestos_tool cloud-provision; then
        echo "Cloud provisioning failed"
        exit 1
    fi
fi

trap "umount /mnt/config" EXIT

mkdir -p /run/config/bootstrap

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

# We populate the NNS public key early since it's used by the guest-upgrade-client which does not depend on
# bootstrap-ic-node.
# populate-nns-public-key reads /run/config/config.json
/opt/ic/bin/config_tool populate-nns-public-key

# Create file under /run/config/guest_vm_type, this can be used to add ConditionPathExists conditions to systemd units
guest_vm_type="$(jq -r ".guest_vm_type" /run/config/config.json)"
if [[ "$guest_vm_type" = null ]]; then
    guest_vm_type=default
fi
mkdir -p "/run/config/guest_vm_type"
touch "/run/config/guest_vm_type/$guest_vm_type"
