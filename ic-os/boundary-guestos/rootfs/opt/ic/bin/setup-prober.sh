#!/bin/bash

set -euox pipefail

readonly RUN_NODE_DIR='/run/ic-node'
readonly NODE_CONFIG_SRC_DIR='/boot/config'
readonly PROBER_CONFIG_SRC_DIR='/boot/config/prober'
readonly PROBER_CONFIG_DST_DIR='/etc/prober'

err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function main() {
    if [[ ! -d "${NODE_CONFIG_SRC_DIR}" ]]; then
        err "missing node configuration directory: ${NODE_CONFIG_SRC_DIR}"
        exit 1
    fi

    if [[ ! -d "${PROBER_CONFIG_SRC_DIR}" ]]; then
        err "missing prober configuration directory: ${PROBER_CONFIG_SRC_DIR}"
        exit 1
    fi

    if [[ ! -d "${PROBER_CONFIG_DST_DIR}" ]]; then
        err "missing prober configuration directory: ${PROBER_CONFIG_DST_DIR}"
        exit 1
    fi

    # Create config dir
    mkdir -p "${RUN_NODE_DIR}/${PROBER_CONFIG_DST_DIR}"

    # Retain pre-existing config
    cp \
        "${PROBER_CONFIG_DST_DIR}"/* \
        "${RUN_NODE_DIR}/${PROBER_CONFIG_DST_DIR}"

    # Setup prober identity
    cp \
        "${PROBER_CONFIG_SRC_DIR}/identity.pem" \
        "${RUN_NODE_DIR}/${PROBER_CONFIG_DST_DIR}/identity.pem"

    # Setup network key
    cat "${RUN_NODE_DIR}/${PROBER_CONFIG_DST_DIR}/ic_public_key.pem" \
        | sed '1d;$d' \
        | tr -d '\n' \
        | base64 -d \
            >"${RUN_NODE_DIR}/${PROBER_CONFIG_DST_DIR}/root_key.der"

    # Setup bind mount
    mount --bind "${RUN_NODE_DIR}/${PROBER_CONFIG_DST_DIR}" "${PROBER_CONFIG_DST_DIR}"
}

main "$@"
