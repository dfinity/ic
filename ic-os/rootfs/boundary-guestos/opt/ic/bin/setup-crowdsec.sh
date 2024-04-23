#!/bin/bash

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly BN_CONFIG="${BOOT_DIR}/bn_vars.conf"

readonly RUN_DIR='/run/ic-node/etc/crowdsec'
readonly CFG_RO="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
readonly CFG_RW="${RUN_DIR}/crowdsec-firewall-bouncer.yaml"

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
            "crowdsec_api_url") API_URL="${value}" ;;
            "crowdsec_api_key") API_KEY="${value}" ;;
        esac
    done <"${BN_CONFIG}"
}

function generate_config() {
    mkdir -p "${RUN_DIR}"
    cp $CFG_RO $CFG_RW
    sed -i "s|{API_URL}|${API_URL}|g" $CFG_RW
    sed -i "s|{API_KEY}|${API_KEY}|g" $CFG_RW
    mount --bind $CFG_RW $CFG_RO
}

function main() {
    read_variables
    generate_config
}

main "$@"
