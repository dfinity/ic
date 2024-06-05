#!/bin/bash

# Encrypt the /boot/config partition

set -e

CONF_PARTITION="$1"

KEYFILE=/boot/grub/store.keyfile

# Check whether there is already a luks header in the partition.
TYPE=$(blkid -o value --match-tag TYPE "${CONF_PARTITION}")

if [ "${TYPE}" == "crypto_LUKS" ]; then
    echo "Found LUKS header in partition ${CONF_PARTITION} for /boot/config."
    cryptsetup luksOpen "${CONF_PARTITION}" conf_crypt --key-file "$KEYFILE"
else
    echo "No LUKS header found in partition ${CONF_PARTITION} for /boot/config. Setting it up on first boot."
    if [[ ! -f "${KEYFILE}" ]]; then
        echo "Generating a key for encrypted partitions"
        umask 0077
        dd if=/dev/random of="$KEYFILE" bs=16 count=1
    fi
    cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${CONF_PARTITION}" "$KEYFILE"
    cryptsetup luksOpen "${CONF_PARTITION}" conf_crypt --key-file "$KEYFILE"
    echo "Populating /boot/config filesystem in ${CONF_PARTITION} on first boot."
    mkfs.ext4 -F /dev/mapper/conf_crypt -d /boot/config
fi
