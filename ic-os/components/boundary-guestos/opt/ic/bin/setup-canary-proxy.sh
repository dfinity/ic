#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'
source '/opt/ic/bin/exec_condition.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"
readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/canary-proxy"

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi

    if [ -f "${BN_CONFIG}" ]; then
        # Read limited set of keys. Be extra-careful quoting values as it could
        # otherwise lead to executing arbitrary shell code!
        while IFS="=" read -r key value; do
            case "${key}" in
                "canary_proxy_port") CANARY_PROXY_PORT="${value}" ;;
            esac
        done <"${BN_CONFIG}"
    fi
}

function generate_config() {
    # skip the ENV_FILE to disable the proxy
    if [[ -z "${CANARY_PROXY_PORT:-}" ]]; then
        echo "canary proxy port not set, disabling canary proxy"
        disable
        return
    fi

    mkdir -p $(dirname "${ENV_FILE}")

    cat >"${ENV_FILE}" <<EOF
CANARY_PROXY_PORT=${CANARY_PROXY_PORT}
EOF
}

function main() {
    read_variables
    generate_config
}

main "$@"
