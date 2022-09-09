#!/bin/bash

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly TMPLT_FILE='/etc/default/denylist-updater'
readonly RUN_DIR='/run/ic-node/etc/default'

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
            "denylist_url") DENYLIST_URL="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/bn_vars.conf"

    if [[ -z "$DENYLIST_URL" ]]; then
        err "missing denylist updater configuration value(s): $(cat "${BOOT_CONFIG}/bn_vars.conf")"
        exit 1
    fi
}

function generate_denylist_updater_config() {
    # Create config dir
    mkdir -p "${RUN_DIR}"

    # Move active configuration and prepare it (use `|` in the `sed` command
    # because it's not a valid URL character)
    cp -a "${TMPLT_FILE}" "${RUN_DIR}/denylist-updater"
    sed -i -e "s|{{DENYLIST_URL}}|${DENYLIST_URL}|g" "${RUN_DIR}/denylist-updater"
}

function main() {
    read_variables
    generate_denylist_updater_config
}

main "$@"
