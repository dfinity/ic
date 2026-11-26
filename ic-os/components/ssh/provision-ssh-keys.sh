#!/bin/bash

# Expects:
# - name of account to install keys for as first argument
# - replacement authorized_keys file on stdin
#
# Exits with a non-zero status if the keys could not be installed or (without
# TEE) persisted, so that the caller can retry.

set -e

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

# Stage the new keys from stdin in a private location (/tmp is a tmpfs). They
# are installed from there, never read back from the "config" partition, which
# the host can modify.
STAGED=$(mktemp)
trap 'rm -f "${STAGED}"' EXIT
cat >"${STAGED}"

GROUP=$(id -ng "${ACCOUNT}")
HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)

# Install the staged keys, set up permissions and label, swap out old keys.
mkdir -p "${HOMEDIR}"
chown "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
chmod 700 "${HOMEDIR}"
runuser -u "${ACCOUNT}" -- sh -c 'umask 077
    mkdir -p "$1/.ssh" && cat >"$1/.ssh/authorized_keys.new" \
        && chmod 600 "$1/.ssh/authorized_keys.new" \
        && mv "$1/.ssh/authorized_keys.new" "$1/.ssh/authorized_keys"' \
    sh "${HOMEDIR}" <"${STAGED}"

chown -R "${ACCOUNT}:${GROUP}" "${HOMEDIR}"
restorecon -r "${HOMEDIR}"

# Without TEE, persist the keys in the "config" partition, from where
# setup-ssh-user-keys.sh restores them at boot (e.g. after an upgrade). This is
# done after installing them, so that a failure here does not hold back e.g. a
# revocation.
#
# With TEE (SEV-SNP), the host can read and write the "config" partition, so it
# is not touched at all: setup-ssh-user-keys.sh does not restore keys from there
# with TEE, and the orchestrator provisions them again after every boot.
#
# sudo resets the environment, so TEE_ENABLED is not available here. Check the
# kernel command line in the same way as 90-sev-status.sh does.
if ! grep -qE "(^|[[:space:]])dfinity\.tee(=|[[:space:]]|$)" /proc/cmdline; then
    mkdir -p /boot/config/accounts_ssh_authorized_keys
    cat "${STAGED}" >"/boot/config/accounts_ssh_authorized_keys/${ACCOUNT}"
fi
