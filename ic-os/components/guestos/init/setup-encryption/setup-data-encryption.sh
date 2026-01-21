#!/bin/bash

set -e

# Get the biggest block device in the system
BASE_DEVICE=$(lsblk -nld --bytes -o SIZE,NAME | sort -n -r | head -n1 | cut -d' ' -f2)

PART_UUID="231213c6-ec9e-11f0-b45f-b7bbea44aaf0"
STORE_DEVICE="/dev/disk/by-partuuid/${PART_UUID}"

# Migration step: change the UUID of the partition to the persistent one
if [ ! -e ${STORE_DEVICE} ] && [ -e /dev/${BASE_DEVICE}10 ]; then
    sfdisk --force --no-reread --part-uuid /dev/${BASE_DEVICE} 10 ${PART_UUID}
    partprobe /dev/${BASE_DEVICE}
fi

if [ -e ${STORE_DEVICE} ]; then
    /opt/ic/bin/guest_disk crypt-open store ${STORE_DEVICE}
    exit 0
fi

echo "start=-, size=-, type=linux, uuid=${PART_UUID}" | sfdisk --force --no-reread -a /dev/${BASE_DEVICE}

# Initialize and open encrypted store.
partprobe /dev/${BASE_DEVICE}

/opt/ic/bin/guest_disk crypt-format store ${STORE_DEVICE}
/opt/ic/bin/guest_disk crypt-open store ${STORE_DEVICE}
