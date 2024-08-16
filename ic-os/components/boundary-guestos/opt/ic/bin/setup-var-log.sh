#!/bin/bash

set -e

blkid /dev/mapper/store-var--log >/dev/null || (
    mkfs.ext4 -F /dev/mapper/store-var--log -d /var/log
)
