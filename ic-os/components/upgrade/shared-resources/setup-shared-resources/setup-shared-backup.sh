#!/bin/bash

echo "Sleeping for debugging purposes..."
sleep 21
echo "Finished sleeping for debugging purposes."

set -e

blkid /dev/mapper/store-shared--backup >/dev/null || (
    mkfs.ext4 /dev/mapper/store-shared--backup
)
