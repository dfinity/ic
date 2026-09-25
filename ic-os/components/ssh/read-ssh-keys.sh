#!/bin/bash

set -e

# Expects:
# - name of account to read keys for as first argument

case "$1" in
    readonly | backup | admin) ;;
    *)
        echo "$0: won't read keys for account '$1'" >&2
        exit 1
        ;;
esac

# Transparently switch uid to root in order to perform the privileged function.
if [ $(id -u) != 0 ]; then
    exec sudo "$0" "$@"
fi

ACCOUNT="$1"

HOMEDIR=$(getent passwd "${ACCOUNT}" | cut -d: -f6)

runuser -u "${ACCOUNT}" -- cat "${HOMEDIR}/.ssh/authorized_keys"
