#!/bin/bash

set -e

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

if [ -e /dev/vda10 ]; then
    #Fix for crypttab
    cp "$KEYFILE" /run/vda10key
    exit 0
fi

echo "- - L" | sfdisk --force --no-reread -a /dev/vda
partprobe /dev/vda

# Generate a key and initialize encrypted store with it.
if [[ ! -f "${KEYFILE}" ]]; then
    # Only in the non-sev case
    umask 0077
    dd if=/dev/random of="$KEYFILE" bs=16 count=1
fi

#Fix for crypttab
cp "$KEYFILE" /run/vda10key

# Set minimal iteration count -- we already use a random key with
# maximal entropy, pbkdf doesn't gain anything (besides slowing
# down boot by a couple seconds which needlessly annoys for testing).
cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vda10 "${KEYFILE}"
