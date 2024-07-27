#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'
source '/opt/ic/bin/exec_condition.shlib'

readonly IDENTITY_PEM="${BOOT_DIR}/prober_identity.pem"

readonly RUN_DIR='/run/ic-node/etc/prober'
readonly ROOT_KEY="${RUN_DIR}/root_key.der"

function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing prober configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    check_nns_pem
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
    get_nns_der >"${ROOT_KEY}"
}

function main() {
    read_variables
    generate_prober_config
}

main "$@"
