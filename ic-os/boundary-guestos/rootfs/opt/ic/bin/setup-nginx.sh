#!/bin/bash

set -ex

if [ -e /boot/config/nns_public_key.pem ]; then
    mkdir -p /run/ic-node/etc/nginx
    cp /boot/config/nns_public_key.pem /run/ic-node/etc/nginx/ic_public_key.pem
    mount --bind /run/ic-node/etc/nginx/ic_public_key.pem /etc/nginx/ic_public_key.pem
fi

restorecon -v /etc/nginx/ic_public_key.pem

function copy_certs() {
    CERT_DIR=/boot/config/certs
    if [[ -f ${CERT_DIR}/fullchain.pem ]] && [[ -f ${CERT_DIR}/privkey.pem ]] && [[ -f ${CERT_DIR}/chain.pem ]]; then
        echo "Using certificates ${CERT_DIR}/fullchain.pem ${CERT_DIR}/privkey.pem ${CERT_DIR}/chain.pem"
        cp ${CERT_DIR}/fullchain.pem /etc/nginx/certs/fullchain.pem
        cp ${CERT_DIR}/privkey.pem /etc/nginx/keys/privkey.pem
        cp ${CERT_DIR}/chain.pem /etc/nginx/certs/chain.pem
    else
        echo "Not copying certificates"
    fi
}

copy_certs
