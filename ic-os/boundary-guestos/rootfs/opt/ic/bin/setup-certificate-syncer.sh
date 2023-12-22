#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'
source '/opt/ic/bin/exec_condition.shlib'

readonly IDENTITY_PEM="${BOOT_DIR}/certificate_issuer_identity.pem"
readonly RAW_DOMAINS="${BOOT_DIR}/raw_domains.txt"

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/certificate-syncer"
readonly CFG_DIR='/run/ic-node/etc/certificate-syncer'
readonly CONFIG_FILE="${BOOT_DIR}/certificate_syncer.conf"

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [ -f "${CONFIG_FILE}" ]; then
        # Read limited set of keys. Be extra-careful quoting values as it could
        # otherwise lead to executing arbitrary shell code!
        while IFS="=" read -r key value; do
            case "${key}" in
                "certificate_syncer_polling_interval_sec") POLLING_INTERVAL_SEC="${value}" ;;
            esac
        done <"${CONFIG_FILE}"
    fi
}

function copy_files() {
    mkdir -p "${CFG_DIR}"

    if [ -f "${RAW_DOMAINS}" ]; then
        RAW_FILE_PATH="${CFG_DIR}/raw_domains.txt"
        cp "${RAW_DOMAINS}" "${RAW_FILE_PATH}"
    fi
}

function generate_config() {
    mkdir -p $(dirname "${ENV_FILE}")

    cat >"${ENV_FILE}" <<EOF
RAW_DOMAINS_PATH=${RAW_FILE_PATH:-}
POLLING_INTERVAL_SEC=${POLLING_INTERVAL_SEC:-}
EOF
}

function main() {
    if [ ! -f "${IDENTITY_PEM}" ]; then
        echo "missing certificate-issuer identity: ${IDENTITY_PEM}, disabling certificate-syncer"
        disable
        return
    fi

    read_variables
    copy_files
    generate_config
}

main "$@"
