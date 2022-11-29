#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly NNS_CONFIG="${BOOT_DIR}/nns.conf"
readonly NNS_PEM="${BOOT_DIR}/nns_public_key.pem"

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/ic-registry-replicator"

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi
    if [ ! -f "${NNS_CONFIG}" ]; then
        err "missing nns configuration: ${NNS_CONFIG}"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "nns_url") NNS_URL="${value}" ;;
        esac
    done <"${NNS_CONFIG}"

    local fail=0
    if [[ -z "${NNS_URL:-}" ]]; then
        err "missing NNS configuration value(s): $(cat "${NNS_CONFIG}")"
        fail=1
    fi

    if [ ! -f "${NNS_PEM}" ]; then
        err "missing nns public key: ${NNS_PEM}"
        fail=1
    fi

    if [[ "${fail}" == 1 ]]; then
        exit 1
    fi
}

function generate_config() {
    mkdir -p "${RUN_DIR}"
    cp -a "${NNS_PEM}" "${RUN_DIR}/"
    cat >"${ENV_FILE}" <<EOF
NNS_URL=${NNS_URL}
EOF
}

function main() {
    read_variables
    generate_config
}

main "$@"
