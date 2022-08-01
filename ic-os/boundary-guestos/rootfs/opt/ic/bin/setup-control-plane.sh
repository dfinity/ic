#!/bin/bash

set -euox pipefail

readonly NNS_CONFIG_PATH='/boot/config/nns.conf'
readonly RUN_NODE_DIR='/run/ic-node'
readonly CONTROL_PLANE_CONFIG_DIR='/etc/control-plane'

err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function main() {
    if [[ ! -f "${NNS_CONFIG_PATH}" ]]; then
        err "missing nns configuration file: ${NNS_CONFIG_PATH}"
        exit 1
    fi

    # Create config dir
    mkdir -p "${RUN_NODE_DIR}/${CONTROL_PLANE_CONFIG_DIR}"

    # Retain pre-existing config
    if [[ -d "${CONTROL_PLANE_CONFIG_DIR}" && "$(ls ${CONTROL_PLANE_CONFIG_DIR})" ]]; then
        cp \
            "${CONTROL_PLANE_CONFIG_DIR}"/* \
            "${RUN_NODE_DIR}/${CONTROL_PLANE_CONFIG_DIR}"
    fi

    cat "${NNS_CONFIG_PATH}" \
        | grep nns_url \
        | cut -d'=' -f2 \
            >"${RUN_NODE_DIR}/${CONTROL_PLANE_CONFIG_DIR}/nns_urls"

    # Create config dir
    if [[ ! -d "${CONTROL_PLANE_CONFIG_DIR}" ]]; then
        mkdir -p "${CONTROL_PLANE_CONFIG_DIR}"
    fi

    # Setup bind mount
    mount --bind \
        "${RUN_NODE_DIR}/${CONTROL_PLANE_CONFIG_DIR}" \
        "${CONTROL_PLANE_CONFIG_DIR}"
}

main "$@"
