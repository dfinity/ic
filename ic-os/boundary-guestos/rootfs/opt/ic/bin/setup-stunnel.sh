#!/bin/bash

set -ex

cp -ar /etc/stunnel/* /run/ic-node/etc/stunnel
mount --bind /run/ic-node/etc/stunnel /etc/stunnel

if [ ! -f /etc/stunnel/stunnel.pem ]; then
    for file in /etc/nginx/keys/privkey.pem /etc/nginx/certs/fullchain.pem; do
        (
            cat $file
            echo
        ) >>/etc/stunnel/stunnel.pem
    done
    chmod 600 /etc/stunnel/stunnel.pem
fi

restorecon -v -r /etc/stunnel
