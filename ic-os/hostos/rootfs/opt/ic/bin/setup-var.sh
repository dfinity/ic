#!/bin/bash

VAR_PARTITION="$1"

echo "Setting up ${VAR_PARTITION} for use as /var."

# The SCSI drives on Supermicro machines are probably discovered asynchronously.
# This issue is not present on Dell machines with NVMe drives. Find a better
# solution to wait for the discovery of attached devices on the PCI bus.
sleep 5

# Check whether there is already a luks header in the partition.
TYPE=$(blkid -o value --match-tag TYPE "${VAR_PARTITION}")

# Defer this because blkid can output "" with a state of 2 if nothing is found
# at all (completely empty partition)
set -e

# cf. the upgrade logic in "manageboot.sh": The target partition is wiped
# clean as part of the upgrade procedure. We can therefore really rely
# on having a clean slate here after first boot of an upgrade.
if [ "${TYPE}" == "ext4" ]; then
    echo "Found ext4 header in partition ${VAR_PARTITION} for /var."
else
    echo "No ext4 header found in partition ${VAR_PARTITION} for /var. Setting it up on first boot."
    mkfs.ext4 -F ${VAR_PARTITION} -d /var
fi
