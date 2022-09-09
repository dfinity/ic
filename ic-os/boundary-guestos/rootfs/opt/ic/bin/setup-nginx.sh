#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly TMPLT_DIR='/etc/nginx/conf.templates'
readonly RUN_DIR='/run/ic-node/etc/nginx'
readonly SNAKEOIL_PEM='/etc/ssl/certs/ssl-cert-snakeoil.pem'
readonly SNAKEOIL_KEY='/etc/ssl/private/ssl-cert-snakeoil.key'

# Place to store the generated routing tables
readonly IC_ROUTING="/var/opt/nginx/ic"

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function read_variables() {
    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing prober configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi

    if [ ! -f "${BOOT_CONFIG}/bn_vars.conf" ]; then
        err "missing domain configuration: ${BOOT_CONFIG}/bn_vars.conf"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "domain") DOMAIN="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/bn_vars.conf"

    if [[ -z "${DOMAIN}" ]]; then
        echo "\${DOMAIN} variable not set. Nginx won't be configured. " 1>&2
        exit 1
    fi
}

function copy_certs() {
    local -r CERT_DIR="${BOOT_CONFIG}/certs"

    mkdir -p "${RUN_DIR}/certs"
    mkdir -p "${RUN_DIR}/keys"

    if [[ -f "${CERT_DIR}/fullchain.pem" ]]; then
        echo "Using certificate ${CERT_DIR}/fullchain.pem"
        cp "${CERT_DIR}/fullchain.pem" "${RUN_DIR}/certs/fullchain.pem"
    else
        echo "Using snakeoil for fullchain.pem"
        cp "${SNAKEOIL_PEM}" "${RUN_DIR}/certs/fullchain.pem"
    fi

    if [[ -f "${CERT_DIR}/chain.pem" ]]; then
        echo "Using certificate ${CERT_DIR}/chain.pem"
        cp "${CERT_DIR}/chain.pem" "${RUN_DIR}/certs/chain.pem"

    else
        echo "Using snakeoil for chain.pem"
        cp "${SNAKEOIL_PEM}" "${RUN_DIR}/certs/chain.pem"
    fi

    if [[ -f "${CERT_DIR}/privkey.pem" ]]; then
        echo "Using certificate ${CERT_DIR}/privkey.pem"
        cp "${CERT_DIR}/privkey.pem" "${RUN_DIR}/keys/privkey.pem"
    else
        echo "Using snakeoil for privkey.pem"
        cp "${SNAKEOIL_KEY}" "${RUN_DIR}/keys/privkey.pem"
    fi
}

function copy_deny_list() {
    DENY_LIST_SRC="/boot/config/denylist.map"
    DENY_LIST_DST="/var/opt/nginx/denylist/denylist.map"

    if [[ ! -f "${DENY_LIST_SRC}" ]]; then
        touch "${DENY_LIST_DST}"
    else
        cp "${DENY_LIST_SRC}" "${DENY_LIST_DST}"
    fi
}

function setup_domain_name() {
    local DOMAIN_ESCAPED=${DOMAIN//\./\\.}

    cp -r "${TMPLT_DIR}/." "${RUN_DIR}/conf.d"

    sed -i \
        -e "s/{{DOMAIN}}/${DOMAIN}/g" \
        -e "s/{{DOMAIN_ESCAPED}}/${DOMAIN_ESCAPED}/g" \
        "${RUN_DIR}/conf.d/"*
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
    restorecon -v /etc/nginx/ic/*
}

function main() {
    read_variables
    copy_certs
    copy_deny_list
    setup_domain_name
    writable_nginx_ic
    restore_context
}

main "$@"
