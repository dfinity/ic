#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

CONFIG_DIR="/config"
CONFIG_TMP="/var/ic/config"
CONFIG_INI="${CONFIG_DIR}/config.ini"
CONFIG_INI_CLONE="${CONFIG_TMP}/config.ini"
SSH_AUTHORIZED_KEYS="${CONFIG_DIR}/ssh_authorized_keys"
SSH_AUTHORIZED_KEYS_CLONE="${CONFIG_TMP}/ssh_authorized_keys"

# Define empty variables so they are not unset
ipv6_prefix=""
ipv6_gateway=""

function print_config_file() {
    if [ -e "${CONFIG_INI}" ]; then
        echo "Found ${CONFIG_INI}. Contents:"
        cat "${CONFIG_INI}"
    else
        log_and_halt_installation_on_error "1" "config.ini not found. Please copy a valid config.ini to the SetupOS installer config partition."
    fi

}

function create_config_tmp() {
    if [ ! -e "${CONFIG_TMP}" ]; then
        # Create fresh config tmp directory
        mkdir -p "${CONFIG_TMP}"
        log_and_halt_installation_on_error "${?}" "Unable to create new '${CONFIG_TMP}' directory."
    fi
}

function clone_config() {
    cp "${CONFIG_INI}" "${CONFIG_INI_CLONE}"
    log_and_halt_installation_on_error "${?}" "Unable to copy 'config.ini' configuration file."

    if [ ! -f "${CONFIG_INI_CLONE}" ]; then
        log_and_halt_installation_on_error "1" "Cloned 'config.ini' configuration file does not exist."
    fi

    if [ -f "${CONFIG_DIR}/node_operator_private_key.pem" ]; then
        cp ${CONFIG_DIR}/node_operator_private_key.pem ${CONFIG_TMP}/node_operator_private_key.pem
        log_and_halt_installation_on_error "${?}" "Unable to copy 'node_operator_private_key.pem' configuration file."
    fi

    if [ -d "${SSH_AUTHORIZED_KEYS}" ]; then
        cp -r "${SSH_AUTHORIZED_KEYS}" "${CONFIG_TMP}"
        log_and_halt_installation_on_error "${?}" "Unable to copy 'ssh_authorized_keys' directory."
    else
        log_and_halt_installation_on_error "1" "Unable to read 'ssh_authorized_keys' directory."
    fi

    if [ ! -d "${SSH_AUTHORIZED_KEYS_CLONE}" ]; then
        log_and_halt_installation_on_error "1" "Cloned 'ssh_authorized_keys' directory does not exist."
    fi
}

function normalize_config() {
    CONFIG_VAR=$(cat "${CONFIG_INI_CLONE}" | tr '\r' '\n')
    echo "${CONFIG_VAR}" >"${CONFIG_INI_CLONE}"

    sed -i 's/#.*$//g' "${CONFIG_INI_CLONE}"
    log_and_halt_installation_on_error "${?}" "Unable to remove comments from 'config.ini'."

    sed -i 's/"//g' "${CONFIG_INI_CLONE}"
    log_and_halt_installation_on_error "${?}" "Unable to replace double-quote characters in 'config.ini'."

    sed -i "s/'//g" "${CONFIG_INI_CLONE}"
    log_and_halt_installation_on_error "${?}" "Unable to replace single-quote characters in 'config.ini'."

    sed -i 's/.*/\L&/' "${CONFIG_INI_CLONE}"
    log_and_halt_installation_on_error "${?}" "Unable to convert upper- to lower-case in 'config.ini'."

    sed -i '/^$/d' "${CONFIG_INI_CLONE}"
    log_and_halt_installation_on_error "${?}" "Unable to remove empty lines in 'config.ini'."

    echo -e '\n' >>"${CONFIG_INI_CLONE}"
    log_and_halt_installation_on_error "${?}" "Unable to inject extra new-line at the end of 'config.ini'."
}

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_prefix") ipv6_prefix="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
        esac
    done <"${CONFIG_INI_CLONE}"
}

function verify_variables() {
    if [ -z "${ipv6_prefix}" ]; then
        log_and_halt_installation_on_error "1" "Variable 'ipv6_prefix' is not defined in 'config.ini'."
    fi

    if [ -z "${ipv6_gateway}" ]; then
        log_and_halt_installation_on_error "1" "Variable 'ipv6_gateway' is not defined in 'config.ini'."
    fi
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    print_config_file
    create_config_tmp
    clone_config
    normalize_config
    read_variables
    verify_variables
    log_end "$(basename $0)"
}

main
