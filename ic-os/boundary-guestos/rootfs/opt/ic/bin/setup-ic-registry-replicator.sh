#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly TMPLT_FILE='/etc/default/ic-registry-replicator.tmplt'
readonly RUN_DIR="/run/ic-node/etc/default"

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
    if [ ! -f "${BOOT_CONFIG}/nns.conf" ]; then
        err "missing nns configuration: ${BOOT_CONFIG}/nns.conf"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "${key}" in
            "nns_url") NNS_URL="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/nns.conf"

    if [[ -z "${NNS_URL:-}" ]]; then
        err "missing NNS configuration value(s): $(cat "${BOOT_CONFIG}/nns.conf")"
        exit 1
    fi
}

function generate_config() {
    # Create config dir
    mkdir -p "${RUN_DIR}"

    readonly ENV_FILE=$(basename ${TMPLT_FILE} .tmplt)

    # Move active configuration and prepare it (use `|` in the `sed` command
    # because it's not a valid URL character)
    cp -a "${TMPLT_FILE}" "${RUN_DIR}/${ENV_FILE}"
    sed -i -e "s|{{NNS_URL}}|${NNS_URL}|g" "${RUN_DIR}/${ENV_FILE}"
}

function main() {
    read_variables
    generate_config
}

main "$@"
