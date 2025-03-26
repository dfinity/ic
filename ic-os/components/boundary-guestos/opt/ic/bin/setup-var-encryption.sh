#!/bin/bash

set -e

VAR_PARTITION="$1"

KEYFILE=/boot/grub/store.keyfile

echo "Setting up ${VAR_PARTITION} for use as encrypted /var."

# Check whether there is already a luks header in the partition.
TYPE=$(blkid -o value --match-tag TYPE "${VAR_PARTITION}")

# cf. the upgrade logic in "manageboot.sh": The target partition is wiped
# clean as part of the upgrade procedure. We can therefore really rely
# on having a clean slate here after first boot of an upgrade.
if [ "${TYPE}" == "crypto_LUKS" ]; then
    echo "Found LUKS header in partition ${VAR_PARTITION} for /var."
    cryptsetup luksOpen "${VAR_PARTITION}" var_crypt --key-file "${KEYFILE}"
else
    echo "No LUKS header found in partition ${VAR_PARTITION} for /var. Setting it up on first boot."
    if [[ ! -f "${KEYFILE}" ]]; then
        echo "Generating a key for encrypted partitions"
        umask 0077
        dd if=/dev/random of="$KEYFILE" bs=16 count=1
    fi
    cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${VAR_PARTITION}" "${KEYFILE}"
    cryptsetup luksOpen "${VAR_PARTITION}" var_crypt --key-file "${KEYFILE}"
    echo "Populating /var filesystem in ${VAR_PARTITION} on first boot."
    mkfs.ext4 -F /dev/mapper/var_crypt -d /var
fi
