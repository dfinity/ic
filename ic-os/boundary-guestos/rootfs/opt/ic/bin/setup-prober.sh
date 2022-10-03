#!/bin/bash

set -euox pipefail

readonly BOOT_DIR='/boot/config/prober'
readonly PROBER_CONFIG="${BOOT_DIR}/prober.disabled"
readonly IDENTITY_PEM="${BOOT_DIR}/identity.pem"
readonly NNS_PEM="${BOOT_DIR}/nns_public_key.pem"

readonly RUN_DIR='/run/ic-node/etc/prober'
readonly DISABLE_FILE="${RUN_DIR}/prober.disabled"
readonly ROOT_KEY="${RUN_DIR}/root_key.der"

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing prober configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [[ -f "${PROBER_CONFIG}" ]]; then
        PROBER_DISABLED="true"
        return
    fi

    if [ ! -f "${IDENTITY_PEM}" ]; then
        err "missing prober identity: ${IDENTITY_PEM}"
        exit 1
    fi

    if [ ! -f "${NNS_PEM}" ]; then
        err "missing nns public key: ${NNS_PEM}"
        exit 1
    fi
}

function generate_prober_config() {
    # Create config dir
    mkdir -p "${RUN_DIR}"

    # Setup enable/disable flag
    if [[ "${PROBER_DISABLED}" == "true" ]]; then
        touch "${DISABLE_FILE}"
        return
    fi

    # Setup prober identity
    cp "${IDENTITY_PEM}" "${RUN_DIR}/"

    # Setup network key
    sed '1d;$d' <"${NNS_PEM}" | tr -d '\n' | base64 -d >"${ROOT_KEY}"

}
function main() {
    read_variables
    generate_prober_config
}

main "$@"
