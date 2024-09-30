#!/bin/bash

set -e

blkid /dev/mapper/store-shared--crypto >/dev/null || (
    mkfs.ext4 /dev/mapper/store-shared--crypto

    # Reload keys, if backed up
    if [ -f /boot/config/REDEPLOY ]; then
        if [ -f /tmp/preserve/crypto.part ]; then
            dd if=/tmp/preserve/crypto.part of=/dev/mapper/store-shared--crypto
            rm -rf /tmp/preserve
            rm -rf /boot/config/REDEPLOY
            echo "Node keys successfully restored."
        fi
    fi
)
