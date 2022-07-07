#!/usr/bin/env bash

set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

CONFIG_DIR="/config"
CONFIG_TMP="/config/tmp"
CONFIG="/config/config.ini"
CONFIG_CLONE="/config/tmp/config.ini"
SSH_AUTHORIZED_KEYS="/config/ssh_authorized_keys"
SSH_AUTHORIZED_KEYS_CLONE="/config/tmp/ssh_authorized_keys"

function create_config_tmp() {
    if [ ! -w "${CONFIG_DIR}" ]; then
        log_and_reboot_on_error "1" "Config partition is not writable."
    fi

    # Remove existing config tmp directory if it exists
    if [ -d "${CONFIG_TMP}" ]; then
        rm -rf "${CONFIG_TMP}"
        log_and_reboot_on_error "${?}" "Unable to remove existing '${CONFIG_TMP}' directory."
    fi

    if [ ! -e "${CONFIG_TMP}" ]; then
        # Create fresh config tmp directory
        mkdir "${CONFIG_TMP}"
        log_and_reboot_on_error "${?}" "Unable to create new '${CONFIG_TMP}' directory."
    fi
}

function clone_config() {
    if [ -f "${CONFIG}" ]; then
        cp "${CONFIG}" "${CONFIG_CLONE}"
        log_and_reboot_on_error "${?}" "Unable to copy 'config.ini' configuration file."
    else
        log_and_reboot_on_error "1" "Unable to read 'config.ini' configuration file."
    fi

    if [ ! -f "${CONFIG_CLONE}" ]; then
        log_and_reboot_on_error "1" "Cloned 'config.ini' configuration file does not exist."
    fi

    if [ -d "${SSH_AUTHORIZED_KEYS}" ]; then
        cp -r "${SSH_AUTHORIZED_KEYS}" "${CONFIG_TMP}"
        log_and_reboot_on_error "${?}" "Unable to copy 'ssh_authorized_keys' directory."
    else
        log_and_reboot_on_error "1" "Unable to read 'ssh_authorized_keys' directory."
    fi

    if [ ! -d "${SSH_AUTHORIZED_KEYS_CLONE}" ]; then
        log_and_reboot_on_error "1" "Cloned 'ssh_authorized_keys' directory does not exist."
    fi
}

function normalize_config() {
    sed -i '/^#.*$/d' "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to remove comments from 'config.ini'."

    sed -i 's/\r$//g' "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to convert end-of-line character from macOS to Unix in 'config.ini'."

    sed -i 's/^M$//g' "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to convert end-of-line character from Windows to Unix in 'config.ini'."

    sed -i 's/"//g' "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to replace double-quote characters in 'config.ini'."

    sed -i "s/'//g" "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to replace single-quote characters in 'config.ini'."

    sed -i 's/.*/\L&/' "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to convert upper- to lower-case in 'config.ini'."

    sed -i 's/ipv6_\+/\n&/g' "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to insert new-line in-front of each variable in 'config.ini'."

    sed -i '/^$/d' "${CONFIG_CLONE}"
    log_and_reboot_on_error "${?}" "Unable to remove empty lines in 'config.ini'."
}

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_prefix") ipv6_prefix="${value}" ;;
            "ipv6_subnet") ipv6_subnet="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
        esac
    done <"${CONFIG_CLONE}"
}

function verify_variables() {
    if [ -z "${ipv6_prefix}" ]; then
        log_and_reboot_on_error "1" "Variable 'ipv6_prefix' is not defined in 'config.ini'."
    fi

    if [ -z "${ipv6_subnet}" ]; then
        log_and_reboot_on_error "1" "Variable 'ipv6_subnet' is not defined in 'config.ini'."
    fi

    if [ -z "${ipv6_gateway}" ]; then
        log_and_reboot_on_error "1" "Variable 'ipv6_gateway' is not defined in 'config.ini'."
    fi
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    create_config_tmp
    clone_config
    normalize_config
    read_variables
    verify_variables
    log_end "$(basename $0)"
}

main
