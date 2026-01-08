#!/bin/bash

set -e

if [ -e /dev/sda ]; then
    BASE_DEVICE="/dev/sda"
elif [ -e /dev/vda ]; then
    BASE_DEVICE="/dev/vda"
else
    echo "Unable to determine base block device"
    exit 1
fi

PART_UUID="231213c6-ec9e-11f0-b45f-b7bbea44aaf0"
STORE_DEVICE="/dev/disk/by-partuuid/${PART_UUID}"

if [ -e ${STORE_DEVICE} ]; then
    /opt/ic/bin/guest_disk crypt-open store ${STORE_DEVICE}
    exit 0
fi

echo "start=-, size=-, type=linux, uuid=${PART_UUID}" | sfdisk --force --no-reread -a ${BASE_DEVICE}

# Initialize and open encrypted store.
partprobe ${BASE_DEVICE}

/opt/ic/bin/guest_disk crypt-format store ${STORE_DEVICE}
/opt/ic/bin/guest_disk crypt-open store ${STORE_DEVICE}
