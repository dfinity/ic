#!/bin/bash

set -e

# Set up ssh keys for the role accounts: This is required to allow
# key-based login to these accounts

for ACCOUNT in backup readonly admin; do
    HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)
    GROUP=$(id -ng "${ACCOUNT}")

    mkdir -p "${HOMEDIR}/.ssh"
    chmod 700 "${HOMEDIR}" "${HOMEDIR}/.ssh"

    AUTHORIZED_SSH_KEYS="/boot/config/accounts_ssh_authorized_keys/${ACCOUNT}"
    if [ -e "${AUTHORIZED_SSH_KEYS}" ]; then
        cp -L "${AUTHORIZED_SSH_KEYS}" "${HOMEDIR}/.ssh/authorized_keys"
        chmod 600 "${HOMEDIR}/.ssh/authorized_keys"
    fi

    chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
    restorecon -r "${HOMEDIR}"
done
