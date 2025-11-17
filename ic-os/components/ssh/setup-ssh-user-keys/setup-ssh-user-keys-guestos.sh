#!/bin/bash

set -e

source /opt/ic/bin/config.sh

copy_ssh_keys() {
    local SOURCE_FILE="$1"
    local DEST_FILE="$2"
    if [ -e "${SOURCE_FILE}" ]; then
        echo "Copying SSH keys from ${SOURCE_FILE} to ${DEST_FILE}"
        cp -L "${SOURCE_FILE}" "${DEST_FILE}"
        chmod 600 "${DEST_FILE}"
    else
        echo "SSH key source file ${SOURCE_FILE} not found, skipping"
    fi
}

# Create home directories
echo "Creating user home directories"
for ACCOUNT in backup readonly admin; do
    HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)
    echo "Creating home directory for ${ACCOUNT}: ${HOMEDIR}"
    mkdir -p "${HOMEDIR}"
done

# Setup SSH keys
echo "Setting up SSH keys for accounts"
for ACCOUNT in backup readonly admin; do
    HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)
    GROUP=$(id -ng "${ACCOUNT}")

    mkdir -p "${HOMEDIR}/.ssh"
    chmod 700 "${HOMEDIR}" "${HOMEDIR}/.ssh"

    GUESTOS_AUTHORIZED_SSH_KEYS="/boot/config/accounts_ssh_authorized_keys/${ACCOUNT}"
    AUTHORIZED_KEYS_FILE="${HOMEDIR}/.ssh/authorized_keys"

    if [ "$SEV_ACTIVE" = 0 ]; then
        echo "SEV/TEE is not active - SSH key copying is enabled"
        copy_ssh_keys "${GUESTOS_AUTHORIZED_SSH_KEYS}" "${AUTHORIZED_KEYS_FILE}"
    else
        echo "SEV/TEE is active - SSH key copying is disabled"
    fi

    chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
    restorecon -r "${HOMEDIR}"
done
