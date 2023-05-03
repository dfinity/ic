#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly RUN_DIR='/run/ic-node/etc/nginx'
readonly EMPTY_NJS_EXPORTS='let v = {}; export default v; // PLACEHOLDER'

API_DOMAINS=()

function read_variables() {
    local -r BN_CONFIG="${BOOT_DIR}/bn_vars.conf"

    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [ ! -f "${BN_CONFIG}" ]; then
        err "missing domain configuration: ${BN_CONFIG}"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "api_domains") API_DOMAINS+=("${value}") ;;
        esac
    done <"${BN_CONFIG}"

    if [[ "${#API_DOMAINS[@]}" -eq 0 ]]; then
        err "API_DOMAINS variable not set. Nginx won't be configured."
        exit 1
    fi
}

function copy_certs() {
    local -r SNAKEOIL_PEM='/etc/ssl/certs/ssl-cert-snakeoil.pem'
    local -r CERT_SRC="${BOOT_DIR}/certs"
    local -r CERT_DST="${RUN_DIR}/certs"
    local -r CERTS=("fullchain.pem" "chain.pem")
    mkdir -p "${CERT_DST}"
    for CERT in "${CERTS[@]}"; do
        if [[ -f "${CERT_SRC}/${CERT}" ]]; then
            echo "Using certificate ${CERT_SRC}/${CERT}"
            cp "${CERT_SRC}/${CERT}" "${CERT_DST}/${CERT}"
        else
            echo "Using snakeoil for ${CERT}"
            cp "${SNAKEOIL_PEM}" "${CERT_DST}/${CERT}"
        fi
    done

    local -r SNAKEOIL_KEY='/etc/ssl/private/ssl-cert-snakeoil.key'
    local -r KEYS_SRC="${CERT_SRC}"
    local -r KEYS_DST="${RUN_DIR}/keys"
    local -r KEYS=("privkey.pem")
    mkdir -p "${KEYS_DST}"
    for KEY in "${KEYS[@]}"; do
        if [[ -f "${KEYS_SRC}/${KEY}" ]]; then
            echo "Using certificate ${KEYS_SRC}/${KEY}"
            cp "${KEYS_SRC}/${KEY}" "${KEYS_DST}/${KEY}"
        else
            echo "Using snakeoil for ${KEY}"
            cp "${SNAKEOIL_KEY}" "${KEYS_DST}/${KEY}"
        fi
    done
}

function setup_domains() {
    local -r DOMAIN_DIR="${RUN_DIR}/conf.d"
    mkdir -p "${DOMAIN_DIR}"

    # api domains
    for DOMAIN in "${API_DOMAINS[@]}"; do
        echo "server_name ${DOMAIN};" >>"${DOMAIN_DIR}/api_domain.conf"
    done
}

function setup_ic_router() {
    local -r SNAKEOIL_PEM='/etc/ssl/certs/ssl-cert-snakeoil.pem'
    local -r IC_ROUTING='/var/opt/nginx/ic'
    local -r IC_LEGACY_ROUTING='/var/cache/ic_routes'
    local -r TRUSTED_CERTS="${IC_ROUTING}/trusted_certs.pem"
    local -r NGINX_TABLE="${IC_ROUTING}/ic_upstreams.conf"
    local -r IC_ROUTER_TABLE="${IC_ROUTING}/ic_routes.js"

    # Place to store the generated routing tables
    mkdir -p "${IC_ROUTING}" "${IC_LEGACY_ROUTING}"

    # trusted_cert.pem contains all certificates for the upstream replica. This file
    # is periodically updated by the proxy+watcher service. To bootstrap the process
    # we initially place a dummy trusted cert. This dummy is the copy of the
    # snakeoil cert. This allows the nginx service to start, but upstream routing
    # will only happen once the control plane pulls the initial set of routes
    if [[ ! -f "${TRUSTED_CERTS}" ]]; then
        cp "${SNAKEOIL_PEM}" "${TRUSTED_CERTS}"
    fi

    if [[ ! -f "${NGINX_TABLE}" ]]; then
        echo '# PLACEHOLDER' >"${NGINX_TABLE}"
    fi

    if [[ ! -f "${IC_ROUTER_TABLE}" ]]; then
        echo "${EMPTY_NJS_EXPORTS}" >"${IC_ROUTER_TABLE}"
    fi
}

function main() {
    read_variables
    copy_certs
    setup_domains
    setup_ic_router
}

main "$@"
