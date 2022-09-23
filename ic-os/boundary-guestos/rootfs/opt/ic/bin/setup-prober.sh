#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config/prober'
readonly RUN_DIR='/run/ic-node/etc/prober'

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function read_variables() {
    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing prober configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi

    if [[ -f "${BOOT_CONFIG}/prober.disabled" ]]; then
        PROBER_DISABLED="true"
        return
    fi

    if [ ! -f "${BOOT_CONFIG}/identity.pem" ]; then
        err "missing prober identity: ${BOOT_CONFIG}/identity.pem"
        exit 1
    fi

    if [ ! -f "${BOOT_CONFIG}/nns_public_key.pem" ]; then
        err "missing nns public key: ${BOOT_CONFIG}/nns_public_key.pem"
        exit 1
    fi
}

function generate_prober_config() {
    # Create config dir
    mkdir -p "${RUN_DIR}"

    # Setup enable/disable flag
    if [[ "${PROBER_DISABLED}" == "true" ]]; then
        touch "${RUN_DIR}/prober.disabled"
        return
    fi

    # Setup prober identity
    cp "${BOOT_CONFIG}/identity.pem" "${RUN_DIR}/identity.pem"

    # Setup network key
    cat "${BOOT_CONFIG}/nns_public_key.pem" \
        | sed '1d;$d' \
        | tr -d '\n' \
        | base64 -d \
            >"${RUN_DIR}/root_key.der"

}
function main() {
    read_variables
    generate_prober_config
}

main "$@"
