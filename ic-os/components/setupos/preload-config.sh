#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

CONFIG_OVERRIDE_PATH="/dev/disk/by-label/OVERRIDE"
CONFIG_DIR="/config"
DATA_DIR="/data"

source /opt/ic/bin/functions.sh

# Clone configuration from "OVERRIDE" USB (used in testing)
function clone_from_usb() {
    if [ ! -b "${CONFIG_OVERRIDE_PATH}" ]; then
        return
    fi

    TMPDIR=$(mktemp -d)
    mount "${CONFIG_OVERRIDE_PATH}" "${TMPDIR}"
    tar xf "${TMPDIR}/config.tar" --no-same-permissions --no-same-owner -C "${CONFIG_DIR}"
    tar xf "${TMPDIR}/data.tar" --no-same-permissions --no-same-owner -C "${DATA_DIR}"
    umount "${TMPDIR}"
    rm -rf "${TMPDIR}"
}

# Establish run order
main() {
    log_start "$(basename $0)"
    clone_from_usb
    log_end "$(basename $0)"
}

main
