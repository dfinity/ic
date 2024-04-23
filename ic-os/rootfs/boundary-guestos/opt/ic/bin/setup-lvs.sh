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

pvs /dev/mapper/vda10-crypt >/dev/null 2>&1 || (
    echo "Volume group 'store' does not exist yet (first boot?), creating it."
    retry vgcreate --force store /dev/mapper/vda10-crypt
    retry vgchange --force -a y
)

# Set up log store if it does not exist yet.
lvs /dev/store/var-log >/dev/null 2>&1 || (
    echo "Logical volume 'var-log' does not exist yet (first boot?), creating it."
    TOTAL_SIZE=$(($(blockdev --getsz /dev/mapper/vda10-crypt) * 512))
    # Limit to 40G or 50% of capacity, whichever is lower.
    LV_SIZE=$(("$TOTAL_SIZE" / 2 / 1024 / 1024))
    LV_SIZE_LIMIT=40000
    if [ "${LV_SIZE}" -gt "${LV_SIZE_LIMIT}" ]; then
        LV_SIZE="${LV_SIZE_LIMIT}"
    fi
    retry lvcreate --yes -L "$LV_SIZE"M -n var-log store
)
