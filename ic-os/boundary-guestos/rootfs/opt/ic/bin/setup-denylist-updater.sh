#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/exec_condition.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"

readonly RUN_DIR='/run/ic-node/etc/default'
readonly ENV_FILE="${RUN_DIR}/denylist-updater"

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi
    if [ ! -f "${BN_CONFIG}" ]; then
        err "missing domain configuration: ${BN_CONFIG}"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "denylist_url") DENYLIST_URL="${value}" ;;
        esac
    done <"${BN_CONFIG}"
}

function generate_denylist_updater_config() {
    # skip the ENV_FILE to disable the updater
    if [[ -z "${DENYLIST_URL:-}" ]]; then
        echo "denylist url not set, disabling denylist updater"
        disable
        return
    fi

    mkdir -p "${RUN_DIR}"
    cat >"${ENV_FILE}" <<EOF
DENYLIST_URL=${DENYLIST_URL}
EOF
}

function main() {
    read_variables
    generate_denylist_updater_config
}

main "$@"
