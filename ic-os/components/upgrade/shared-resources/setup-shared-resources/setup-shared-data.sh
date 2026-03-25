#!/bin/bash

set -e

DEVICE=/dev/mapper/store-shared--data

echo "Checking if ${DEVICE} has a valid filesystem..."
if ! blkid "${DEVICE}" >/dev/null 2>&1; then
    echo "No filesystem exists on ${DEVICE}, creating one..."
    mkfs.xfs -m crc=1,reflink=1 "${DEVICE}"
    exit 0
fi

DATA_MOUNT="/mnt"
cleanup() {
    mountpoint -q "${DATA_MOUNT}" && umount "${DATA_MOUNT}" || true
    rm -rf "${DATA_MOUNT}" || true
}
trap cleanup EXIT

echo "Performing a test mount of ${DEVICE} to ${DATA_MOUNT} to check filesystem health..."
if MOUNT_OUTPUT=$(mount -t xfs "${DEVICE}" "${DATA_MOUNT}" 2>&1); then
    echo "Mount succeeded, filesystem is healthy. Unmounting ${DATA_MOUNT}..."
    umount "${DATA_MOUNT}" || echo "Warning: umount ${DATA_MOUNT} failed, EXIT trap will retry." >&2
    exit 0
fi

echo "Mounting ${DEVICE} failed with error: '${MOUNT_OUTPUT}'. Calling xfs_repair -L ..."
xfs_repair -L "${DEVICE}"
