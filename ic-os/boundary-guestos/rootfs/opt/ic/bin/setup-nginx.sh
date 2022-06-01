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

function copy_deny_list() {
    DENY_LIST=/boot/config/denylist.map
    if [[ -f ${DENY_LIST} ]]; then
        cp $DENY_LIST /etc/nginx/denylist.map
    fi
}

function restore_context() {
    restorecon -v /etc/nginx/ic_public_key.pem
    restorecon -v /etc/nginx/certs/fullchain.pem
    restorecon -v /etc/nginx/keys/privkey.pem
    restorecon -v /etc/nginx/certs/chain.pem
    restorecon -v /etc/nginx/conf.d/*.conf
    restorecon -v /etc/nginx/denylist.map
}

function setup_domain_name() {
    source /boot/config/nginxdomain.conf
    if [[ -z "$DOMAIN" ]] || [[ -z "$TLD" ]]; then
        echo "\$DOMAIN or \$TLD variable not set. Nginx won't be configured. " 1>&2
        exit 1
    fi
    pushd /etc/nginx/conf.d
    for filename in ./001-mainnet-nginx.conf ./002-rosetta-nginx.conf ./999-test-ic-nginx.conf.exclude; do
        sed -i -e "s/{{DOMAIN}}/${DOMAIN}/g" -e "s/{{TLD}}/${TLD}/g" ${filename}
    done
    popd
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
copy_deny_list
setup_domain_name
enable_dev_mode
restore_context
