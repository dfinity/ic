#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly BOOT_CONFIG_PROBER="${BOOT_CONFIG}/prober"
readonly PROBER_CONFIG_DIR='/etc/prober'
readonly RUN_DIR="/run/ic-node/etc/prober"

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

function main() {
    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing node configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi

    if [[ ! -d "${BOOT_CONFIG_PROBER}" ]]; then
        err "missing prober configuration directory: ${BOOT_CONFIG_PROBER}"
        exit 1
    fi

    if [[ ! -d "${PROBER_CONFIG_DIR}" ]]; then
        err "missing prober configuration directory: ${PROBER_CONFIG_DIR}"
        exit 1
    fi

    # Create config dir
    mkdir -p "${RUN_DIR}"

    # Retain pre-existing config
    cp \
        "${PROBER_CONFIG_DIR}"/* \
        "${RUN_DIR}"

    # Setup prober identity
    cp \
        "${BOOT_CONFIG_PROBER}/identity.pem" \
        "${RUN_DIR}/identity.pem"

    # Setup network key
    cat "${RUN_DIR}/ic_public_key.pem" \
        | sed '1d;$d' \
        | tr -d '\n' \
        | base64 -d \
            >"${RUN_DIR}/root_key.der"

    # Setup enable/disable flag
    if [[ -f "${BOOT_CONFIG_PROBER}/prober.disabled" ]]; then
        cp \
            "${BOOT_CONFIG_PROBER}/prober.disabled" \
            "${RUN_DIR}/prober.disabled"
    fi

    # Setup bind mount
    mount --bind "${RUN_DIR}" "${PROBER_CONFIG_DIR}"
}

main "$@"
