#!/bin/bash

set -e

DEVICE=/dev/mapper/store-shared--data

if ! blkid "${DEVICE}" >/dev/null 2>&1; then
    # No filesystem exists, create one.
    mkfs.xfs -m crc=1,reflink=1 "${DEVICE}"
else
    # Filesystem exists. Try a test mount to verify it is healthy.
    # This also replays the XFS journal if it is dirty (normal after a crash).
    TESTMOUNT=$(mktemp -d)
    if mount -t xfs "${DEVICE}" "${TESTMOUNT}" 2>/dev/null; then
        # Mount succeeded, filesystem is healthy.
        umount "${TESTMOUNT}"
    else
        # Mount failed, filesystem is corrupted.
        # Attempt xfs_repair first; if that also fails, reformat.
        # The IC node will recover its state via state sync so no data
        # is permanently lost.
        if ! xfs_repair "${DEVICE}" 2>&1; then
            echo "xfs_repair failed on ${DEVICE}, reformatting."
            mkfs.xfs -f -m crc=1,reflink=1 "${DEVICE}"
        fi
    fi
    rmdir "${TESTMOUNT}" 2>/dev/null || true
fi
