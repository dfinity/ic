#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'
source '/opt/ic/bin/exec_condition.shlib'

readonly IDENTITY_PEM="${BOOT_DIR}/certificate_issuer_identity.pem"
readonly RAW_DOMAINS="${BOOT_DIR}/raw_domains.txt"

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/certificate-syncer"
readonly CFG_DIR='/run/ic-node/etc/certificate-syncer'

function copy_files() {
    mkdir -p "${CFG_DIR}"
    cp "${RAW_DOMAINS}" "${CFG_DIR}/raw_domains.txt"
}

function generate_config() {
    mkdir -p $(dirname "${ENV_FILE}")
    if [ -f "${RAW_DOMAINS}" ]; then
        cat >"${ENV_FILE}" <<EOF
RAW_DOMAINS_PATH=${CFG_DIR}/raw_domains.txt
EOF
    else
        cat >"${ENV_FILE}" <<EOF
RAW_DOMAINS_PATH=
EOF
    fi
}

function main() {
    if [ ! -f "${IDENTITY_PEM}" ]; then
        echo "missing certificate-issuer identity: ${IDENTITY_PEM}, disabling certificate-syncer"
        disable
        return
    fi

    if [ -f "${RAW_DOMAINS}" ]; then
        copy_files
    fi

    generate_config
}

main "$@"
