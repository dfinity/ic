#!/bin/bash

set -e

# Retry a command a couple of times. The reason we do this is that the
# VG may "spuriously" fail:
# - for safety, the VG tools open their underlying device in O_EXCL mode
# - this ensures that nobody else has the device open
# - there are however some asynchronous probing processes running in the
#   system (presumably triggered by dbus) that also take a brief look at each
#   device as it is created
# So there is the possibility of a temporary access race, it happens
# infrequently but sufficiently often in testing. It is correct to simply
# retry until we manage to successfully get exclusive access.
#
# One annoying issue, though: It is not possible to determine the cause of
# the operation failure by the exit code. For the most part, the lvm tools
# simply return with exit code 5 to indicate "any kind of error", but we
# we would of course prefer to only retry on exclusive access violations.
# To cope with the possibility of other (permanent) error conditions, give
# up after a couple of retries.
function retry() {
    local NRETRIES=10
    while [ "$NRETRIES" -gt 0 ]; do
        if "$@"; then return 0; fi
        echo "Operation failed, retrying."
        sleep 1
        NRETRIES=$(("$NRETRIES" - 1))
    done
    echo "Operation failed 10 times, giving up."
    return 1
}

pvs /dev/mapper/store-crypt >/dev/null 2>&1 || (
    echo "Volume group 'store' does not exist yet (first boot?), creating it."
    retry vgcreate --force store /dev/mapper/store-crypt
    retry vgchange --force -a y
)

# Set up crypto data store if it does not exist yet.
lvs /dev/store/shared-crypto >/dev/null 2>&1 || (
    echo "Logical volume 'shared-crypto' does not exist yet (first boot?), creating it."
    LV_SIZE_MB=1024
    retry lvcreate --yes -L "$LV_SIZE_MB"M -n shared-crypto store
)

# Set up state data store if it does not exist yet.
lvs /dev/store/shared-data >/dev/null 2>&1 || (
    echo "Logical volume 'shared-data' does not exist yet (first boot?), creating it."
    # For now, only use 25% of available capacity.
    TOTAL_SIZE_MB=$(($(blockdev --getsz /dev/mapper/store-crypt) * 512 / 1024 / 1024))
    LV_SIZE_MB=$(("$TOTAL_SIZE_MB" / 4))
    retry lvcreate --yes -L "$LV_SIZE_MB"M -n shared-data store
)

TOTAL_SIZE_MB=$(($(blockdev --getsz /dev/mapper/store-crypt) * 512 / 1024 / 1024))
# Limit to 500G or 25% of capacity, whichever is lower.
LV_SIZE_MB=$(("$TOTAL_SIZE_MB" / 4))
LV_SIZE_LIMIT_MB=500000
if [ "${LV_SIZE_MB}" -gt "${LV_SIZE_LIMIT_MB}" ]; then
    LV_SIZE_MB="${LV_SIZE_LIMIT_MB}"
fi

# Set up backup data store if it does not exist yet.
lvs /dev/store/shared-backup >/dev/null 2>&1 || (
    echo "Logical volume 'shared-backup' does not exist yet (first boot?), creating it."
    retry lvcreate --yes -L "$LV_SIZE_MB"M -n shared-backup store
)

# TODO(NODE-1722): remove once every GuestOS has been upgraded after the LV resize
# We use sectors because lvs outputs MB in ##.00 format which is annoying to compare since we don't
# have bc in GuestOS.
SECTORS_PER_MB=2048
if (($(lvs --noheadings --nosuffix --units 's' -o lv_size /dev/mapper/store-shared--backup) < (LV_SIZE_MB * SECTORS_PER_MB))); then
    echo "Resizing logical volume 'shared-backup' to ${LV_SIZE_MB}MB."
    retry lvresize --yes -L "$LV_SIZE_MB"M -n /dev/mapper/store-shared--backup
fi

# Set up swap space if it does not exist yet.
lvs /dev/store/shared-swap >/dev/null 2>&1 || (
    echo "Logical volume 'shared-swap' does not exist yet (first boot?), creating it."
    TOTAL_SIZE_MB=$(($(blockdev --getsz /dev/mapper/store-crypt) * 512 / 1024 / 1024))
    # Limit to 128G or 1% of capacity, whichever is lower.
    LV_SIZE_MB=$(("$TOTAL_SIZE_MB" / 100))
    LV_SIZE_LIMIT_MB=128000
    if [ "${LV_SIZE_MB}" -gt "${LV_SIZE_LIMIT_MB}" ]; then
        LV_SIZE_MB="${LV_SIZE_LIMIT_MB}"
    fi
    retry lvcreate --yes -L "$LV_SIZE_MB"M -n shared-swap store
)
