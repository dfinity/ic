#!/bin/bash

set -e

if [ -e /dev/vda10 ]; then
    exit 0
fi

echo "- - L" | sfdisk --force --no-reread -a /dev/vda

# Initialize encrypted store.
partprobe /dev/vda
# Set minimal iteration count -- we already use a random key with
# maximal entropy, pbkdf doesn't gain anything (besides slowing
# down boot by a couple seconds which needlessly annoys for testing).
cryptsetup luksFormat --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vda10 /boot/config/store.keyfile
