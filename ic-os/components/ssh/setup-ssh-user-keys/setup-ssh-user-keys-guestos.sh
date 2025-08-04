#!/bin/bash

set -e

source /opt/ic/bin/config.sh

copy_ssh_keys() {
    local SOURCE_FILE="$1"
    local DEST_FILE="$2"
    if [ -e "${SOURCE_FILE}" ]; then
        cp -L "${SOURCE_FILE}" "${DEST_FILE}"
        chmod 600 "${DEST_FILE}"
    fi
}

ENABLE_TEE=$(get_config_value '.icos_settings.enable_trusted_execution_environment')

for ACCOUNT in backup readonly admin; do
    HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)
    GROUP=$(id -ng "${ACCOUNT}")

    mkdir -p "${HOMEDIR}/.ssh"
    chmod 700 "${HOMEDIR}" "${HOMEDIR}/.ssh"

    GUESTOS_AUTHORIZED_SSH_KEYS="/boot/config/accounts_ssh_authorized_keys/${ACCOUNT}"
    AUTHORIZED_KEYS_FILE="${HOMEDIR}/.ssh/authorized_keys"

    if [ "${ENABLE_TEE}" != "true" ]; then
        copy_ssh_keys "${GUESTOS_AUTHORIZED_SSH_KEYS}" "${AUTHORIZED_KEYS_FILE}"
    fi

    chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
    restorecon -r "${HOMEDIR}"
done
