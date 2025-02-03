#!/bin/bash

set -e

if [ -e /dev/vda10 ]; then
    exit 0
fi

# this command creates a partition that is not aligned to 4k sectors.
# however we need alignment to 4k sectors for the encryption to work.
# so we need to create a partition that is aligned to 4k sectors.

# -n will not commit the changes to the disk. It will only print the changes.
echo "- - L" | sfdisk -n --force --no-reread -a /dev/vda
# check the start and end sectors of the partition.
# the output looks like this:
# Device          Start         End     Sectors  Size Type
# /dev/vda1        2048      206847      204800  100M EFI System
# /dev/vda2      206848      411647      204800  100M Linux filesystem
# /dev/vda3      411648      616447      204800  100M Linux filesystem
# /dev/vda4      616448     2713599     2097152    1G Linux filesystem
# /dev/vda5     2713600    23685119    20971520   10G Linux filesystem
# /dev/vda6    23685120    44656639    20971520   10G Linux filesystem
# /dev/vda7    44656640    46753791     2097152    1G Linux filesystem
# /dev/vda8    46753792    67725311    20971520   10G Linux filesystem
# /dev/vda9    67725312    88696831    20971520   10G Linux filesystem
# /dev/vda10   88696832  2236180479  2147483648    1T Linux filesystem
# The partition table is unchanged (--no-act).
# get the line for /dev/vda10 and get the start sector.
start_sector=$(echo "- - L" | sfdisk -n --force --no-reread -a /dev/vda | grep /dev/vda10 | awk '{print $2}')
# get the end sector.
end_sector=$(echo "- - L" | sfdisk -n --force --no-reread -a /dev/vda | grep /dev/vda10 | awk '{print $3}')
# check if the start sector is aligned to 4kb sectors.
# if the start sector is not aligned to 4kb sectors, we need to align it.
if [ $((start_sector * 512 % 4096)) -ne 0 ]; then
    # align the start sector to 4kb sectors.
    start_sector=$((start_sector + ((start_sector * 512) % 4096) / 512))
fi
# check if the end sector is aligned to 4kb sectors.
# if the end sector is not aligned to 4kb sectors, we need to align it.
if [ $((end_sector * 512 % 4096)) -ne 0 ]; then
    # align the end sector to 4kb sectors.
    end_sector=$((end_sector + ((end_sector * 512) % 4096) / 512))
fi

# run the sfdisk command to create the partition.
echo "$start_sector $end_sector L" | sfdisk --force --no-reread -a /dev/vda 


# Generate a key and initialize encrypted store with it.
partprobe /dev/vda
umask 0077
dd if=/dev/random of=/boot/config/store.keyfile bs=16 count=1
# Set minimal iteration count -- we already use a random key with
# maximal entropy, pbkdf doesn't gain anything (besides slowing
# down boot by a couple seconds which needlessly annoys for testing).
cryptsetup luksFormat --type luks2 --sector-size 4096 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 /dev/vda10 /boot/config/store.keyfile
