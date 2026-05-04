#!/bin/bash

set -e

blkid /dev/mapper/store-shared--backup >/dev/null || (
    mkfs.ext4 /dev/mapper/store-shared--backup
)

# TODO(NODE-1722): remove once every GuestOS has been upgraded after the LV resize
# NOTE: e2fsck will exit non-zero if errors are fixed. Rather than handle these
# cases (1, 2), ignore them, and let any real errors fall to the resize or
# later mount.
e2fsck -pf /dev/mapper/store-shared--backup || true
resize2fs /dev/mapper/store-shared--backup
