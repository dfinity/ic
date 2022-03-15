#!/bin/bash

set -ex

if [ -e /boot/config/nns_public_key.pem ]; then
    mkdir -p /run/ic-node/etc/nginx
    cp /boot/config/nns_public_key.pem /run/ic-node/etc/nginx/ic_public_key.pem
    mount --bind /run/ic-node/etc/nginx/ic_public_key.pem /etc/nginx/ic_public_key.pem
fi

restorecon -v /etc/nginx/ic_public_key.pem
