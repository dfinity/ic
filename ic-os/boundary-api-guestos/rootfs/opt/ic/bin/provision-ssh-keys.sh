#!/bin/bash

# Expects:
# - name of account to install keys for as first argument
# - replacement authorized_keys file on stdin

ACCOUNT="$1"

# Location of master configuration
ORIGIN="/boot/config/accounts_ssh_authorized_keys/${ACCOUNT}"

# Ensure config directory exists
mkdir -p /boot/config/accounts_ssh_authorized_keys

# Write new key file into master location from stdin
# Use of stdin is intentional to avoid file storage
# for keys
cat >"${ORIGIN}"

GROUP=$(id -ng "${ACCOUNT}")
HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)

# Ensure directory and authorized_keys file exist, just in case they were not
# set up earlier. This actually should not happen, just to be safe.
if [ ! -e "${HOMEDIR}/.ssh" -o ! -e "${HOMEDIR}/.ssh/authorized_keys" ]; then
    mkdir -p "${HOMEDIR}/.ssh"
    touch "${HOMEDIR}/.ssh/authorized_keys"
    chmod 700 "${HOMEDIR}"
    chmod 700 "${HOMEDIR}/.ssh"
    chmod 600 "${HOMEDIR}/.ssh/authorized_keys"
    chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
    restorecon -r "${HOMEDIR}"
fi

# Transfer keys from master location, set up permissions and label, swap
# out old keys.
cp "${ORIGIN}" "${HOMEDIR}/.ssh/authorized_keys.new"
chmod 600 "${HOMEDIR}/.ssh/authorized_keys.new"
chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
chcon --reference="${HOMEDIR}/.ssh/authorized_keys" "${HOMEDIR}/.ssh/authorized_keys.new"
mv "${HOMEDIR}/.ssh/authorized_keys.new" "${HOMEDIR}/.ssh/authorized_keys"
