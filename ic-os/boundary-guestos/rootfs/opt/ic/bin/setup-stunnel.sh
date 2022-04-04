#!/bin/bash

set -ex

if [ ! -f /etc/stunnel/stunnel.pem ]; then
    for file in /etc/nginx/keys/privkey.pem /etc/nginx/certs/fullchain.pem; do
        (
            cat $file
            echo
        ) >>/etc/stunnel/stunnel.pem
    done
    chmod 644 /etc/stunnel/stunnel.pem
fi
