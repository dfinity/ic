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

for ACCOUNT in backup readonly admin; do
    HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)
    GROUP=$(id -ng "${ACCOUNT}")

    mkdir -p "${HOMEDIR}/.ssh"
    chmod 700 "${HOMEDIR}" "${HOMEDIR}/.ssh"

    HOSTOS_AUTHORIZED_SSH_KEYS="/boot/config/ssh_authorized_keys/${ACCOUNT}"
    AUTHORIZED_KEYS_FILE="${HOMEDIR}/.ssh/authorized_keys"

    copy_ssh_keys "${HOSTOS_AUTHORIZED_SSH_KEYS}" "${AUTHORIZED_KEYS_FILE}"

    chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
    restorecon -r "${HOMEDIR}"
done
