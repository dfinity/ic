#!/bin/bash

set -e

VAR_PARTITION="$1"

echo "Seting up ${VAR_PARTITION} for use as encrypted /var."

# Check whether there is already a luks header in the partition.
TYPE=$(blkid -o value --match-tag TYPE "${VAR_PARTITION}")

# cf. the upgrade logic in "manageboot.sh": The target partition is wiped
# clean as part of the upgrade procedure. We can therefore really rely
# on having a clean slate here after first boot of an upgrade.
if [ "${TYPE}" == "crypto_LUKS" ]; then
    echo "Found LUKS header in partition ${VAR_PARTITION} for /var."
    cryptsetup luksOpen "${VAR_PARTITION}" var_crypt --key-file /boot/config/store.keyfile
else
    echo "No LUKS header found in partition ${VAR_PARTITION} for /var. Setting it up on first boot."
    # Set minimal iteration count -- we already use a random key with
    # maximal entropy, pbkdf doesn't gain anything (besides slowing
    # down boot by a couple seconds which needlessly annoys for testing).
    cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${VAR_PARTITION}" /boot/config/store.keyfile
    cryptsetup luksOpen "${VAR_PARTITION}" var_crypt --key-file /boot/config/store.keyfile
    echo "Populating /var filesystem in ${VAR_PARTITION} on first boot."
    mkfs.ext4 -F /dev/mapper/var_crypt -d /var
fi
