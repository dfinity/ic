#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly TMPLT_FILE='/etc/default/icx-proxy.tmplt'
readonly RUN_DIR='/run/ic-node/etc/default'

INVALID_SSL=

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    local -r CERT_DIR="${BOOT_CONFIG}/certs"

    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing node configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi
    if [ ! -f "${BOOT_CONFIG}/bn_vars.conf" ]; then
        err "missing domain configuration: ${BOOT_CONFIG}/bn_vars.conf"
        exit 1
    fi

    # Disable SSL checking if we don't have real certs
    if [[ ! -f "${CERT_DIR}/fullchain.pem" ]] || [[ ! -f "${CERT_DIR}/privkey.pem" ]] || [[ ! -f "${CERT_DIR}/chain.pem" ]]; then
        SSL_OPTIONS="--danger-accept-invalid-ssl"
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "domain") DOMAIN="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/bn_vars.conf"

    if [[ -z "${DOMAIN:-}" ]]; then
        err "missing domain configuration value(s): $(cat "${BOOT_CONFIG}/bn_vars.conf")"
        exit 1
    fi
}

function generate_icx_proxy_config() {
    # Create config dir
    mkdir -p "${RUN_DIR}"

    # Move configuration and prepare it
    cp -a "${TMPLT_FILE}" "$RUN_DIR/icx-proxy"
    sed -i \
        -e "s/{{DOMAIN}}/${DOMAIN}/g" \
        -e "s/{{SSL_OPTIONS}}/${SSL_OPTIONS:-}/g" \
        "$RUN_DIR/icx-proxy"
}

function main() {
    read_variables
    generate_icx_proxy_config
}

main "$@"
