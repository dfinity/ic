#!/bin/bash

set -e

if [ -e /dev/vda10 ]; then
    exit 0
fi

DISK="/dev/vda"
PARTITION="/dev/vda10"

start_sector=$(echo "- - L" | sfdisk -n --force --no-reread -a $DISK | grep $PARTITION  | grep -v "Created" | awk '{print $2}')
end_sector=$(echo "- - L" | sfdisk -n --force --no-reread -a $DISK | grep $PARTITION  | grep -v "Created" | awk '{print $3}')

# Ensure the start sector is a multiple of 8 (aligned to 4KiB)
if [ $((start_sector % 8)) -ne 0 ]; then
    start_sector=$(( (start_sector + 7) / 8 * 8 ))  # Round up to the next multiple of 8
fi

# Ensure the end sector is a multiple of 8 (aligned to 4KiB), rounding down
if [ $((end_sector % 8)) -ne 0 ]; then
    end_sector=$((end_sector / 8 * 8))
fi

partition_size=$((end_sector - start_sector + 1))
# Ensure that the partition size is a multiple of 8 (aligned to 4KiB), rounding down
if [ $((partition_size % 8)) -ne 0 ]; then
    partition_size=$((partition_size / 8 * 8))
fi

echo "$start_sector, $partition_size, L" | sfdisk --force --no-reread -a /dev/vda


# Generate a key and initialize encrypted store with it.
partprobe /dev/vda
umask 0077
dd if=/dev/random of=/boot/config/store.keyfile bs=16 count=1
# Set minimal iteration count -- we already use a random key with
# maximal entropy, pbkdf doesn't gain anything (besides slowing
# down boot by a couple seconds which needlessly annoys for testing).
cryptsetup luksFormat --type luks2 --sector-size 4096 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vda10 /boot/config/store.keyfile
