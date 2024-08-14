#!/bin/bash

set -e

blkid /dev/mapper/store-shared--backup >/dev/null || (
    mkfs.ext4 /dev/mapper/store-shared--backup
)
