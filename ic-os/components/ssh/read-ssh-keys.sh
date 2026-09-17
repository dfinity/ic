#!/bin/bash

set -e

# Transparently switch uid to root in order to perform the privileged function.
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

# Expects:
# - name of account to read keys for as first argument

ACCOUNT="$1"

HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)

runuser -u "${ACCOUNT}" -- cat "${HOMEDIR}/.ssh/authorized_keys"
