#!/bin/bash

set -euox pipefail

readonly BOOT_DIR='/boot/config'
readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"
readonly CERT_DIR="${BOOT_DIR}/certs"
readonly CERTS=("fullchain.pem" "privkey.pem" "chain.pem")

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/icx-proxy"

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {

    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi
    if [ ! -f "${BN_CONFIG}" ]; then
        err "missing domain configuration: ${BN_CONFIG}"
        exit 1
    fi

    # Disable SSL checking if we don't have real certs
    for CERT in "${CERTS[@]}"; do
        if [[ ! -f "${CERT_DIR}/${CERT}" ]]; then
            echo "missing cert ${CERT_DIR}/${CERT}, disabling ssl"
            SSL_OPTIONS="--danger-accept-invalid-ssl"
        fi
    done

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "domain") DOMAIN="${value}" ;;
        esac
    done <"${BN_CONFIG}"

    if [[ -z "${DOMAIN:-}" ]]; then
        err "missing domain configuration value(s): $(cat "${BN_CONFIG}")"
        exit 1
    fi
}

function generate_icx_proxy_config() {
    mkdir -p "${RUN_DIR}"
    cat >"${ENV_FILE}" <<EOF
DOMAIN=${DOMAIN}
SSL_OPTIONS=${SSL_OPTIONS:-}
EOF
}

function main() {
    read_variables
    generate_icx_proxy_config
}

main "$@"
