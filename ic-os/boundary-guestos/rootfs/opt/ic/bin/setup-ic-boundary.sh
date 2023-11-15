#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly SERVICE_NAME='ic-boundary'

readonly NNS_CONFIG="${BOOT_DIR}/nns.conf"
readonly NNS_PEM="${BOOT_DIR}/nns_public_key.pem"

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/${SERVICE_NAME}"

function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [ ! -f "${NNS_CONFIG}" ]; then
        err "missing nns configuration: ${NNS_CONFIG}"
        exit 1
    fi

    if [ ! -f "${NNS_PEM}" ]; then
        err "missing nns public key: ${NNS_PEM}"
        exit 1
    fi

    while IFS="=" read -r key value; do
        case "${key}" in
            "nns_url") NNS_URL="${value}" ;;
        esac
    done <"${NNS_CONFIG}"

    if [[ -z "${NNS_URL:-}" ]]; then
        err "missing NNS configuration value(s): $(cat "${NNS_CONFIG}")"
        exit 1
    fi
}

function generate_config() {
    mkdir -p "${RUN_DIR}"

    # Copy NNS Public Key
    cp -a "${NNS_PEM}" "${RUN_DIR}/"

    # Generate Configuration
    cat >"${ENV_FILE}" <<EOF
NNS_URL=${NNS_URL}
RPS_LIMIT_SUBNET=300
CACHE_SIZE=1073741824
CACHE_ITEM_MAX_SIZE=65536
CACHE_TTL=1
EOF
}

function main() {
    read_variables
    generate_config
    mkdir -p /var/opt/registry/store
}

main "$@"
