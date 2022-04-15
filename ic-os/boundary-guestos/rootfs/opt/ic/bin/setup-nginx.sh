#!/bin/bash

set -ex

function copy_nns_url() {
    if [ -e /boot/config/nns_public_key.pem ]; then
        mkdir -p /run/ic-node/etc/nginx
        cp /boot/config/nns_public_key.pem /run/ic-node/etc/nginx/ic_public_key.pem
        mount --bind /run/ic-node/etc/nginx/ic_public_key.pem /etc/nginx/ic_public_key.pem
    fi
}

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

function restore_context() {
    restorecon -v /etc/nginx/ic_public_key.pem
    restorecon -v /etc/nginx/certs/fullchain.pem
    restorecon -v /etc/nginx/keys/privkey.pem
    restorecon -v /etc/nginx/certs/chain.pem
    restorecon -v /etc/nginx/conf.d/*.conf
}

function enable_dev_mode() {
    # The boundary node image is built in prod configuration. Any changes need
    # to enable development mode at runtime should go in here.
    if [ $(cat /boot/config/deployment_type) == "dev" ]; then
        pushd /etc/nginx/conf.d
        mv ./999-test-ic-nginx.conf.exclude ./999-test-ic-nginx.conf
        mv ./001-mainnet-nginx.conf ./001-mainnet-nginx.conf.exclude
        mv ./002-rosetta-nginx.conf ./002-rosetta-nginx.conf.exclude
        popd
    fi
}

copy_nns_url
copy_certs
enable_dev_mode
restore_context
