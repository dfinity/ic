#!/bin/bash

set -e

if [ -e /boot/config/guestos_type/upgrade ]; then
  /opt/ic/bin/upgrade-client --replica-config-file /run/ic-node/config/ic.json5
  poweroff
else
#if echo $encryption_key | cryptsetup luksOpen /dev/vda10 vda10-crypt -; then
  if cryptsetup luksOpen /dev/vda10 vda10-crypt --key-file /var/store.keyfile; then
    echo "Successfully decrypted /dev/vda10"
  else
    echo "Successfully decrypted /dev/vda10"
    exit 1
fi

