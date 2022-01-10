#!/bin/bash

set -e

# Set up ssh keys for the role accounts: This is required to allow
# key-based login to these accounts

# TBD (NODE-248): should only allow root ssh key for test builds

mount --bind /run/ic-node/root/.ssh /root/.ssh

for ACCOUNT in root backup readonly admin; do
    ORIGIN="/boot/config/accounts_ssh_authorized_keys/${ACCOUNT}"
    if [ -e "${ORIGIN}" ]; then
        HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)
        GROUP=$(id -ng "${ACCOUNT}")
        mkdir -p "${HOMEDIR}/.ssh"
        cp "${ORIGIN}" "${HOMEDIR}/.ssh/authorized_keys"
        chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}/.ssh"
        restorecon -vr "${HOMEDIR}/.ssh"
    fi
done
