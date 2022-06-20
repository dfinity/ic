#!/bin/bash

set -e

pvs /dev/mapper/vda10-crypt >/dev/null 2>&1 || (
    echo "Volume group 'store' does not exist yet (first boot?), creating it."
    vgcreate --force store /dev/mapper/vda10-crypt
    vgchange --force -a y
)

# Set up nginx data store if it does not exist yet.
lvs /dev/store/nginx-cache >/dev/null 2>&1 || (
    echo "Logical volume 'nginx-cache' does not exist yet (first boot?), creating it."
    # Limit to 25% of capacity.
    TOTAL_SIZE=$(($(blockdev --getsz /dev/mapper/vda10-crypt) * 512))
    LV_SIZE=$(("$TOTAL_SIZE" / 4 / 1024 / 1024))
    lvcreate --yes -L "$LV_SIZE"M -n nginx-cache store
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
    lvcreate --yes -L "$LV_SIZE"M -n var-log store
)
