#!/bin/bash

set -e

source /opt/ic/bin/config.sh

read_config_variables() {
    authorized_ssh_keys=$(get_config_value '.icos_settings.ssh_authorized_keys_path')
}

copy_ssh_keys() {
    local SOURCE_FILE="$1"
    local DEST_FILE="$2"
    if [ -e "${SOURCE_FILE}" ]; then
        cp -L "${SOURCE_FILE}" "${DEST_FILE}"
        chmod 600 "${DEST_FILE}"
    fi
}

read_config_variables

for ACCOUNT in backup readonly admin; do
    HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)
    GROUP=$(id -ng "${ACCOUNT}")

    mkdir -p "${HOMEDIR}/.ssh"
    chmod 700 "${HOMEDIR}" "${HOMEDIR}/.ssh"

    AUTHORIZED_SSH_KEYS="${authorized_ssh_keys}/${ACCOUNT}"
    AUTHORIZED_KEYS_FILE="${HOMEDIR}/.ssh/authorized_keys"

    copy_ssh_keys "${AUTHORIZED_SSH_KEYS}" "${AUTHORIZED_KEYS_FILE}"

    chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
    restorecon -r "${HOMEDIR}"
done
