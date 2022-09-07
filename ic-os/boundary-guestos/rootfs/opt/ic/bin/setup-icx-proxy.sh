#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly ICX_PROXY_CONFIG_DIR='/etc/icx-proxy'
readonly RUN_DIR="/run/ic-node/etc/icx-proxy"

INVALID_SSL="false"

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing node configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi
    if [[ ! -f "${BOOT_CONFIG}/icx-proxy.conf" ]]; then
        err "missing icx-proxy configuration: ${BOOT_CONFIG}/icx-proxy.conf"
        exit 1
    fi
    if [ ! -f "${BOOT_CONFIG}/bn_vars.conf" ]; then
        err "missing domain configuration: ${BOOT_CONFIG}/bn_vars.conf"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "invalid_ssl") INVALID_SSL="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/icx-proxy.conf"

    while IFS="=" read -r key value; do
        case "${key}" in
            "domain") DOMAIN="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/bn_vars.conf"

    if [[ -z "$DOMAIN" ]]; then
        err "missing domain configuration value(s): $(cat "${BOOT_CONFIG}/bn_vars.conf")"
        exit 1
    fi
}

function generate_icx_proxy_config() {
    # Move configuration and prepare it
    cp -a "${ICX_PROXY_CONFIG_DIR}/options" "$RUN_DIR/options"
    sed -i -e "s/{{DOMAIN}}/${DOMAIN}/g" "$RUN_DIR/options"

    # Setup any extra configuration options
    if [ "${INVALID_SSL}" == "true" ]; then
        cp -a "${ICX_PROXY_CONFIG_DIR}/invalid-ssl.options" "$RUN_DIR/ssl.options"
    else
        echo "SSL_OPTIONS=" >"${RUN_DIR}/ssl.options"
    fi
}

function main() {
    read_variables
    generate_icx_proxy_config
}

main "$@"
