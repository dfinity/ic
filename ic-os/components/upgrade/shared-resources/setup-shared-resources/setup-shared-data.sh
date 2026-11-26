#!/bin/bash

set -e

# Without a reverse-mapping btree (rmapbt=0), which newer mkfs.xfs versions enable by default: it
# adds metadata to every extent allocation and free, making the checkpoints' syncfs 1.5-1.8x as
# long, and reserves about 1% of the file system.
blkid /dev/mapper/store-shared--data >/dev/null || (
    mkfs.xfs -m crc=1,reflink=1,rmapbt=0 /dev/mapper/store-shared--data
)
