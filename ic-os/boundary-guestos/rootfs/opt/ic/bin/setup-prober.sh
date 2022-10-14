#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/exec_condition.shlib'

readonly BOOT_DIR='/boot/config'
readonly IDENTITY_PEM="${BOOT_DIR}/prober_identity.pem"
readonly NNS_PEM="${BOOT_DIR}/nns_public_key.pem"

readonly RUN_DIR='/run/ic-node/etc/prober'
readonly ROOT_KEY="${RUN_DIR}/root_key.der"

function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing prober configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [ ! -f "${NNS_PEM}" ]; then
        err "missing nns public key: ${NNS_PEM}"
        exit 1
    fi
}

function generate_prober_config() {
    if [ ! -f "${IDENTITY_PEM}" ]; then
        echo "missing prober identity: ${IDENTITY_PEM}, disabling prober"
        disable
        return
    fi

    # Create config dir
    mkdir -p "${RUN_DIR}"

    # Setup prober identity
    cp "${IDENTITY_PEM}" "${RUN_DIR}/identity.pem"

    # Setup network key
    sed '1d;$d' <"${NNS_PEM}" | tr -d '\n' | base64 -d >"${ROOT_KEY}"
}

function main() {
    read_variables
    generate_prober_config
}

main "$@"
