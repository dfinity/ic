#!/bin/bash

echo "Sleeping for debugging purposes..."
sleep 21
echo "Finished sleeping for debugging purposes."

set -e

blkid /dev/mapper/store-shared--data >/dev/null || (
    mkfs.xfs -m crc=1,reflink=1 /dev/mapper/store-shared--data
)
