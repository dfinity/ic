#!/bin/bash

set -e

pvs /dev/mapper/vda10-crypt >/dev/null 2>&1 || (
    echo "Volume group 'store' does not exist yet (first boot?), creating it."
    vgcreate --force store /dev/mapper/vda10-crypt
    vgchange --force -a y
)

# Set up crypto data store if it does not exist yet.
lvs /dev/store/shared-crypto >/dev/null 2>&1 || (
    echo "Logical volume 'shared-crypto' does not exist yet (first boot?), creating it."
    LV_SIZE=1024M
    lvcreate -L "$LV_SIZE"M -n shared-crypto store
)

# Set up state data store if it does not exist yet.
lvs /dev/store/shared-data >/dev/null 2>&1 || (
    echo "Logical volume 'shared-data' does not exist yet (first boot?), creating it."
    # For now, only use 25% of available capacity.
    TOTAL_SIZE=$(($(blockdev --getsz /dev/mapper/vda10-crypt) * 512))
    LV_SIZE=$(("$TOTAL_SIZE" / 4 / 1024 / 1024))
    lvcreate -L "$LV_SIZE"M -n shared-data store
)

# Set up backup data store if it does not exist yet.
lvs /dev/store/shared-backup >/dev/null 2>&1 || (
    echo "Logical volume 'shared-backup' does not exist yet (first boot?), creating it."
    TOTAL_SIZE=$(($(blockdev --getsz /dev/mapper/vda10-crypt) * 512))
    # Limit to 180G or 25% of capacity, whichever is lower.
    LV_SIZE=$(("$TOTAL_SIZE" / 4 / 1024 / 1024))
    LV_SIZE_LIMIT=180000
    if [ "${LV_SIZE}" -gt "${LV_SIZE_LIMIT}" ]; then
        LV_SIZE="${LV_SIZE_LIMIT}"
    fi
    lvcreate -L "$LV_SIZE"M -n shared-backup store
)
