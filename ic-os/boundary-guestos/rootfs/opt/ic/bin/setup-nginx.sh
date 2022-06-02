#!/bin/bash

set -ex

function copy_nns_url() {
    NGINX_RUN="$1"
    if [ -e /boot/config/nns_public_key.pem ]; then
        cp /boot/config/nns_public_key.pem "${NGINX_RUN}"/ic_public_key.pem
        mount --bind "${NGINX_RUN}"/ic_public_key.pem /etc/nginx/ic_public_key.pem
    fi
}

function copy_certs() {
    NGINX_RUN="$1"
    CERT_DIR=/boot/config/certs

    if [[ -f ${CERT_DIR}/fullchain.pem ]] && [[ -f ${CERT_DIR}/privkey.pem ]] && [[ -f ${CERT_DIR}/chain.pem ]]; then
        echo "Using certificates ${CERT_DIR}/fullchain.pem ${CERT_DIR}/privkey.pem ${CERT_DIR}/chain.pem"

        cp ${CERT_DIR}/fullchain.pem "${NGINX_RUN}"/certs/fullchain.pem
        cp ${CERT_DIR}/privkey.pem "${NGINX_RUN}"/keys/privkey.pem
        cp ${CERT_DIR}/chain.pem "${NGINX_RUN}"/certs/chain.pem

        mount --bind "${NGINX_RUN}"/certs /etc/nginx/certs
        mount --bind "${NGINX_RUN}"/keys /etc/nginx/keys
    else
        echo "Not copying certificates"
    fi
}

function copy_deny_list() {
    NGINX_RUN="$1"
    DENY_LIST=/boot/config/denylist.map
    if [[ -f ${DENY_LIST} ]]; then
        cp "${DENY_LIST}" "${NGINX_RUN}"/denylist.map
        mount --bind "${NGINX_RUN}"/denylist.map /etc/nginx/denylist.map
    fi
}

function setup_domain_name() {
    NGINX_RUN="$1"

    cp /etc/nginx/conf.d/* "$NGINX_RUN"/conf.d/
    mount --bind "${NGINX_RUN}"/conf.d /etc/nginx/conf.d

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
    NGINX_RUN="$1"

    # The boundary node image is built in prod configuration. Any changes need
    # to enable development mode at runtime should go in here.
    if [ $(cat /boot/config/deployment_type) == "dev" ]; then
        pushd "$NGINX_RUN"/conf.d
        mv ./999-test-ic-nginx.conf.exclude ./999-test-ic-nginx.conf
        mv ./001-mainnet-nginx.conf ./001-mainnet-nginx.conf.exclude
        mv ./002-rosetta-nginx.conf ./002-rosetta-nginx.conf.exclude
        popd
    fi
}

function restore_context() {
    restorecon -v /etc/nginx/ic_public_key.pem \
        /etc/nginx/certs/fullchain.pem \
        /etc/nginx/keys/privkey.pem \
        /etc/nginx/certs/chain.pem \
        /etc/nginx/conf.d/*.conf \
        /etc/nginx/denylist.map
}

# Place to assemble nginx related configuration for the current run
NGINX_RUN="/run/ic-node/etc/nginx"

copy_nns_url "$NGINX_RUN"
copy_certs "$NGINX_RUN"
copy_deny_list "$NGINX_RUN"
setup_domain_name "$NGINX_RUN"
enable_dev_mode "$NGINX_RUN"
restore_context
