#!/bin/bash

# Initialize configuration in /run/config from config partition.

set -eo pipefail

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

# Log an informational message to both stdout (captured by the journal) and
# /dev/ttyS0 (captured by the host's serial console) so that early-boot
# progress of this service can be observed even when journald forwarding has
# not yet been set up on the VM.
function info() {
    echo "$@"
    echo "init-config: $@" >/dev/ttyS0 || true
}

function mount_config_device() {
    CONFIG_DEVICE="/dev/disk/by-label/CONFIG"
    TIMEOUT="10"
    info "Trigger udev and wait up to ${TIMEOUT} seconds for all events to be handled and exit early if ${CONFIG_DEVICE} appears ..."
    udevadm trigger --subsystem-match=block --action=add
    udevadm settle --timeout="${TIMEOUT}" --exit-if-exists="${CONFIG_DEVICE}"

    info "Checking for ${CONFIG_DEVICE} device"

    # Check if device exists & is a symlink to the real one
    if [ -L "${CONFIG_DEVICE}" ]; then
        info "Found ${CONFIG_DEVICE} device, mounting at /mnt/config"

        # Ensure that the config device is vfat. If we ever change to another filesystem type, we should ensure
        # that it only contains regular files and directories (not symlinks, devices, etc.).
        if mount -t vfat -o ro ${CONFIG_DEVICE} /mnt/config; then
            info "Successfully mounted ${CONFIG_DEVICE} device at /mnt/config"
            return 0
        else
            info "Failed to mount ${CONFIG_DEVICE} device at /mnt/config"
        fi
    fi

    info "No ${CONFIG_DEVICE} device found for mounting"
    return 1
}

# Try config disk first, then run Cloud provisioning if that fails
if ! mount_config_device; then
    info "Config disk not found, trying cloud provisioning"

    # Since root is read-only - mount a tmpfs at /mnt/config to be able to write a config.json there
    mount -t tmpfs config /mnt/config

    if ! /opt/ic/bin/guestos_tool cloud-provision; then
        info "Cloud provisioning failed"
        exit 1
    fi
fi

trap "umount /mnt/config" EXIT

mkdir -p /run/config/bootstrap

cp -r /mnt/config/. /run/config/bootstrap/

if [ -f /run/config/bootstrap/config.json ]; then
    cp /run/config/bootstrap/config.json /run/config/config.json
    chown ic-replica:nogroup /run/config/config.json
else
    info "config.json not found in config partition"
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
