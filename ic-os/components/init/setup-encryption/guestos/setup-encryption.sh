#!/bin/bash

set -e

if [ -f /boot/config/REDEPLOY ]; then
    echo "WARNING! Redeploying node."

    # Backup keys
    cryptsetup luksOpen /dev/vda10 vda10-crypt --key-file /boot/config/store.keyfile
    sleep 5
    mkdir /tmp/preserve
    dd if=/dev/mapper/store-shared--crypto of=/tmp/preserve/crypto.part bs=100M
    vgchange -an store
    cryptsetup luksClose vda10-crypt

    # Trigger "redeployment"
    rm -rf /boot/config/CONFIGURED
    rm -rf /boot/config/store.keyfile
elif [ -e /dev/vda10 ]; then
    exit 0
else
    echo "- - L" | sfdisk --force --no-reread -a /dev/vda
fi

# Generate a key and initialize encrypted store with it.
partprobe /dev/vda
umask 0077
dd if=/dev/random of=/boot/config/store.keyfile bs=16 count=1
# Set minimal iteration count -- we already use a random key with
# maximal entropy, pbkdf doesn't gain anything (besides slowing
# down boot by a couple seconds which needlessly annoys for testing).
cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vda10 /boot/config/store.keyfile
