#!/bin/bash

set -e

blkid /dev/mapper/store-shared--crypto >/dev/null || (
    mkfs.ext4 /dev/mapper/store-shared--crypto
)
