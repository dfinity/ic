#!/bin/bash

set -e

DEVICE=/dev/mapper/store-shared--data

echo "Checking if ${DEVICE} has a valid filesystem..."
if ! blkid "${DEVICE}" >/dev/null 2>&1; then
    echo "No filesystem exists on ${DEVICE}, creating one..."
    mkfs.xfs -f -m crc=1,reflink=1 "${DEVICE}"
else
    echo "Filesystem exists on ${DEVICE}, running xfs_repair to check and repair if necessary..."
    # Filesystem exists. Run xfs_repair to check and fix it.
    # xfs_repair (without -L) is safe: it exits non-zero without modifying
    # anything when the journal is dirty but valid (normal after a crash),
    # telling us to mount the filesystem to replay the log. In that case
    # the real mount (via fstab) will replay the journal automatically.
    if REPAIR_OUTPUT=$(xfs_repair "${DEVICE}" 2>&1); then
        echo "xfs_repair succeeded on ${DEVICE}."
    elif echo "${REPAIR_OUTPUT}" | grep -qi "replay the log"; then
        # Dirty but valid journal. The real mount will replay it.
        echo "XFS journal on ${DEVICE} is dirty but valid; the mount will replay it."
    else
        # Actual corruption. Log the output and try xfs_repair -L to zero
        # the log and repair. If that also fails, reformat as last resort.
        # The IC node will recover its state via state sync so no data is
        # permanently lost.
        echo "xfs_repair failed on ${DEVICE}:"
        echo "${REPAIR_OUTPUT}"
        echo "Calling 'xfs_repair -L' on ${DEVICE}..."
        if ! xfs_repair -L "${DEVICE}"; then
            echo "'xfs_repair -L' failed on ${DEVICE}, reformatting..."
            mkfs.xfs -f -m crc=1,reflink=1 "${DEVICE}"
        fi
    fi
fi
