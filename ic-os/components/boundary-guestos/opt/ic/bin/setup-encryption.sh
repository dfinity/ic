#!/bin/bash

set -e

KEYFILE=/boot/grub/store.keyfile

if [ -e /dev/vda10 ]; then
    #Fix for crypttab
    cp "$KEYFILE" /run/vda10key
    exit 0
fi

echo "- - L" | sfdisk --force --no-reread -a /dev/vda
partprobe /dev/vda

# Generate a key and initialize encrypted store with it.
if [[ ! -f "${KEYFILE}" ]]; then
    umask 0077
    dd if=/dev/random of="$KEYFILE" bs=16 count=1
fi

#Fix for crypttab
cp "$KEYFILE" /run/vda10key

# Set minimal iteration count -- we already use a random key with
# maximal entropy, pbkdf doesn't gain anything (besides slowing
# down boot by a couple seconds which needlessly annoys for testing).
cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vda10 "${KEYFILE}"
