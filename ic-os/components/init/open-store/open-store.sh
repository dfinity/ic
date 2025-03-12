#!/bin/bash

set -e

encryption_key="TEST_ENCRYPTION_KEY"

#if echo $encryption_key | cryptsetup luksOpen /dev/vda10 vda10-crypt -; then
if cryptsetup luksOpen /dev/vda10 vda10-crypt --key-file /boot/config/store.keyfile; then
    echo "Successfully decrypted /dev/vda10"
else
    echo "Could not decrypt /dev/vda10, will try communicating with old VM to set passphrase"
fi

