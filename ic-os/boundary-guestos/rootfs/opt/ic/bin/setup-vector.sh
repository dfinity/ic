#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly VECTOR_CONFIG='/etc/default/vector'
readonly RUN_CONFIG="/run/ic-node/etc/default/vector"

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Read the config variables. The files must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
function read_variables() {
    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing node configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi
    if [ ! -f "${BOOT_CONFIG}/bn_vars.conf" ]; then
        err "missing domain configuration: ${BOOT_CONFIG}/bn_vars.conf"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "elasticsearch_url") ELASTICSEARCH_URL="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/bn_vars.conf"

    if [[ -z "$ELASTICSEARCH_URL" ]]; then
        err "missing vector configuration value(s): $(cat "${BOOT_CONFIG}/bn_vars.conf")"
        exit 1
    fi
}

function generate_vector_config() {
    # Move active configuration and prepare it
    cp -a "${VECTOR_CONFIG}" "${RUN_CONFIG}"
    sed -i -e "s/{{ELASTICSEARCH_URL}}/${ELASTICSEARCH_URL}/g" "${RUN_CONFIG}"
}

function main() {
    read_variables
    generate_vector_config
}

main "$@"
