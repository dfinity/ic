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
    # Ensure cleanup on exit: unmount if still mounted and remove temp dir.
    cleanup() {
        mountpoint -q "${TESTMOUNT}" && umount "${TESTMOUNT}" || true
        rmdir "${TESTMOUNT}" 2>/dev/null || true
    }
    trap cleanup EXIT
    if MOUNT_OUTPUT=$(mount -t xfs "${DEVICE}" "${TESTMOUNT}" 2>&1); then
        # Mount succeeded, filesystem is healthy.
        umount "${TESTMOUNT}"
    else
        # Mount failed, filesystem is corrupted.
        # Log the mount failure output to aid diagnostics.
        echo "Mount of ${DEVICE} on ${TESTMOUNT} failed:" >&2
        echo "${MOUNT_OUTPUT}" >&2
        # Attempt xfs_repair first; if that also fails, try xfs_repair -L,
        # and only then fall back to reformat. The IC node will recover its
        # state via state sync so no data is permanently lost.
        if ! xfs_repair "${DEVICE}"; then
            echo "xfs_repair without log zeroing failed on ${DEVICE}, trying xfs_repair -L." >&2
            if ! xfs_repair -L "${DEVICE}"; then
                echo "xfs_repair -L failed on ${DEVICE}, reformatting." >&2
                mkfs.xfs -f -m crc=1,reflink=1 "${DEVICE}"
            fi
        fi
    fi
    rmdir "${TESTMOUNT}" 2>/dev/null || true
fi
