#!/bin/bash

set -e

blkid /dev/mapper/store-shared--data >/dev/null || (
    mkfs.xfs -m crc=1,reflink=1 /dev/mapper/store-shared--data
)
