#!/bin/bash

# Expects:
# - name of account to install keys for as first argument
# - replacement authorized_keys file on stdin

case "$1" in
    readonly | backup | recovery) ;;
    *)
        echo "$0: won't provision account '$1'" >&2
        exit 1
        ;;
esac

# Transparently switch uid to root in order to perform the privileged function.
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

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

# Transfer keys from master location, set up permissions and label, swap
# out old keys.
mkdir -p "${HOMEDIR}"
chown "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
chmod 700 "${HOMEDIR}"
runuser -u "${ACCOUNT}" -- sh -c 'umask 077
    mkdir -p "$1/.ssh" && cat >"$1/.ssh/authorized_keys.new" \
        && chmod 600 "$1/.ssh/authorized_keys.new" \
        && mv "$1/.ssh/authorized_keys.new" "$1/.ssh/authorized_keys"' \
    sh "${HOMEDIR}" <"${ORIGIN}" || exit 1

chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
restorecon -r "${HOMEDIR}"
