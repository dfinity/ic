#!/bin/bash

set -ex

# Place to assemble nginx related configuration for the current run
NGINX_RUN="/run/ic-node/etc/nginx"

# Place to store the generated routing tables
IC_ROUTING="/var/opt/nginx/ic"

function copy_nns_url() {
    if [ ! -e /boot/config/nns_public_key.pem ]; then
        return
    fi

    cp \
        /boot/config/nns_public_key.pem \
        "${NGINX_RUN}"/ic_public_key.pem

    mount --bind \
        "${NGINX_RUN}"/ic_public_key.pem \
        /etc/nginx/ic_public_key.pem
}

function copy_certs() {
    CERT_DIR=/boot/config/certs

    if [[ ! -f ${CERT_DIR}/fullchain.pem ]] || [[ ! -f ${CERT_DIR}/privkey.pem ]] || [[ ! -f ${CERT_DIR}/chain.pem ]]; then
        echo "Not copying certificates"
        return
    fi

    echo "Using certificates ${CERT_DIR}/fullchain.pem ${CERT_DIR}/privkey.pem ${CERT_DIR}/chain.pem"

    cp ${CERT_DIR}/fullchain.pem "${NGINX_RUN}"/certs/fullchain.pem
    cp ${CERT_DIR}/privkey.pem "${NGINX_RUN}"/keys/privkey.pem
    cp ${CERT_DIR}/chain.pem "${NGINX_RUN}"/certs/chain.pem

    mount --bind "${NGINX_RUN}"/certs /etc/nginx/certs
    mount --bind "${NGINX_RUN}"/keys /etc/nginx/keys
}

function copy_deny_list() {
    DENY_LIST="/boot/config/denylist.map"
    if [[ ! -f ${DENY_LIST} ]]; then
        DENY_LIST="/etc/nginx/denylist.map"
    fi

    cp \
        "${DENY_LIST}" \
        "${NGINX_RUN}"/denylist.map

    mount --bind \
        "${NGINX_RUN}"/denylist.map \
        /etc/nginx/denylist.map
}

function setup_domain_name() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "DOMAIN") DOMAIN="${value}" ;;
            "TLD") TLD="${value}" ;;
        esac
    done </boot/config/nginxdomain.conf

    if [[ -z "${DOMAIN}" ]] || [[ -z "${TLD}" ]]; then
        echo "\${DOMAIN} or \${TLD} variable not set. Nginx won't be configured. " 1>&2
        exit 1
    fi

    DIR_LIST=(
        conf.d
        includes
    )

    DOMAIN_ESCAPED=${DOMAIN//\./\\.}

    for path in "${DIR_LIST[@]}"; do
        cp -r \
            /etc/nginx/${path} \
            ${NGINX_RUN}/

        mount --bind \
            ${NGINX_RUN}/${path} \
            /etc/nginx/${path}

        sed -i \
            -e "s/{{DOMAIN}}/${DOMAIN}/g" \
            -e "s/{{DOMAIN_ESCAPED}}/${DOMAIN_ESCAPED}/g" \
            -e "s/{{TLD}}/${TLD}/g" \
            /etc/nginx/${path}/*
    done
}

function writable_nginx_ic() {
    mkdir -p "${IC_ROUTING}"

    cp -ar \
        /etc/nginx/ic/* \
        "${IC_ROUTING}"

    mount --bind \
        "${IC_ROUTING}" \
        /etc/nginx/ic
}

function restore_context() {
    PATH_LIST=(
        certs/chain.pem
        certs/fullchain.pem
        conf.d/*.conf
        denylist.map
        ic_public_key.pem
        ic/*
        keys/privkey.pem
    )

    for path in "${PATH_LIST[@]}"; do
        restorecon -v /etc/nginx/${path}
    done
}

function main() {
    copy_nns_url
    copy_certs
    copy_deny_list
    setup_domain_name
    writable_nginx_ic
    restore_context
}

main "$@"
