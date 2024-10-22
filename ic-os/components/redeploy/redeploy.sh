#!/bin/bash

set -e

if [ -f /boot/config/REDEPLOY ]; then
    echo "WARNING! Redeploying node."

    # Backup keys
    cryptsetup luksOpen /dev/vda10 vda10-crypt --key-file /boot/config/store.keyfile
    # XXX
    sleep 5
    mkdir /tmp/preserve
    dd if=/dev/mapper/store-shared--crypto of=/tmp/preserve/crypto.part bs=100M
    vgchange -an store
    cryptsetup luksClose vda10-crypt

    # Trigger "redeployment"
    rm -rf /boot/config/CONFIGURED
    rm -rf /boot/config/store.keyfile
fi
