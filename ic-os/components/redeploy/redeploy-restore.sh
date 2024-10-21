#!/bin/bash

set -e

if [ -f /boot/config/REDEPLOY ]; then
    if [ -f /tmp/preserve/crypto.part ]; then
        dd if=/tmp/preserve/crypto.part of=/dev/mapper/store-shared--crypto bs=100M
        rm -rf /tmp/preserve
        rm -rf /boot/config/REDEPLOY
        echo "Node keys successfully restored."
    fi
fi
