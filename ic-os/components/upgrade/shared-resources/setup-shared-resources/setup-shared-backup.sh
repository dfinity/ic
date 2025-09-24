#!/bin/bash

set -e

blkid /dev/mapper/store-shared--backup >/dev/null || (
    mkfs.ext4 /dev/mapper/store-shared--backup
)

# TODO(NODE-1722): remove once every GuestOS has been upgraded after the LV resize
resize2fs /dev/mapper/store-shared--backup
