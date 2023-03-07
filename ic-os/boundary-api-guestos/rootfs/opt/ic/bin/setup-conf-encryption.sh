#!/bin/bash

# Encrypt the /boot/config partition

set -e

CONF_PARTITION="$1"

if [[ -e /dev/sev-guest ]]; then
    # sev-snp enabled
    KEYFILE=/run/key.snp
    if [[ ! -f "${KEYFILE}" ]]; then
        # Derive a sealing key based on the VM's measurement if it hasn't been created already
        /opt/ic/bin/sev-guest-kdf -m "${KEYFILE}"
    fi
else
    KEYFILE=/boot/grub/store.keyfile
fi

# Check whether there is already a luks header in the partition.
TYPE=$(blkid -o value --match-tag TYPE "${CONF_PARTITION}")

if [ "${TYPE}" == "crypto_LUKS" ]; then
    echo "Found LUKS header in partition ${CONF_PARTITION} for /boot/config."
    cryptsetup luksOpen "${CONF_PARTITION}" conf_crypt --key-file "$KEYFILE"
else
    echo "No LUKS header found in partition ${CONF_PARTITION} for /boot/config. Setting it up on first boot."
    if [[ ! -f "${KEYFILE}" ]]; then
        # Only in the non-sev case
        echo "Generating a key for encrypted partitions"
        umask 0077
        dd if=/dev/random of="$KEYFILE" bs=16 count=1
    fi
    cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${CONF_PARTITION}" "$KEYFILE"
    cryptsetup luksOpen "${CONF_PARTITION}" conf_crypt --key-file "$KEYFILE"
    echo "Populating /boot/config filesystem in ${CONF_PARTITION} on first boot."
    mkfs.ext4 -F /dev/mapper/conf_crypt -d /boot/config
fi
