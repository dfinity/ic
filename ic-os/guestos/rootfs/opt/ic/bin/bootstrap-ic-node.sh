#!/bin/bash

# Provision a node based on an injected "ic-bootstrap.tar" file. This script
# is meant to be run as a prerequisite before launching nodemanager/replica.
#
# The configuration format is presently described here:
# https://docs.google.com/document/d/1W2bDkq3xhNvQyWPIVSKpYuBzaa5d1QN-N4uiXByr2Qg/edit
#
# The tar file can be supplied using one of two methods:
# - as "ic-bootstrap.tar" stored on a (virtual) removable media attached
#   on first boot
# - it can be directly "pushed" into the filesystem as /mnt/ic-bootstrap.tar
#   (e.g. bind mount when running the entire stack as docker container)

set -eo pipefail

# List all block devices marked as "removable".
function find_removable_devices() {
    for DEV in $(ls -C /sys/class/block); do
        if [ -e /sys/class/block/"${DEV}"/removable ]; then
            local IS_REMOVABLE=$(cat /sys/class/block/"${DEV}"/removable)
            if [ "${IS_REMOVABLE}" == 1 ]; then
                # If this is a partitioned device (and it usually is), then
                # the first partition is of relevance.
                # return first partition for use instead.
                if [ -e /sys/class/block/"${DEV}1" ]; then
                    local TGT="/dev/${DEV}1"
                elif [ -e /sys/class/block/"${DEV}p1" ]; then
                    local TGT="/dev/${DEV}p1"
                else
                    local TGT="/dev/${DEV}"
                fi
                # Sanity check whether device is usable (it could be a
                # CD drive with no medium in)
                if blockdev "$TGT" >/dev/null 2>/dev/null; then
                    echo "$TGT"
                fi
            fi
        fi
    done
}

# Process the bootstrap package given as first argument to populate
# both config space and
# parts of /var/lib/ic/data and /var/lib/ic/crypto
#
# Arguments:
# - $1: path to the bootstrap package (typically /mnt/ic-bootstrap.tar)
# - $2: path to config space (typically /boot/config)
# - $3: path to ic storage root (typically /var/lib/ic)
function process_bootstrap() {
    local BOOTSTRAP_TAR="$1"
    local CONFIG_ROOT="$2"
    local STATE_ROOT="$3"

    local TMPDIR=$(mktemp -d)
    tar xf "${BOOTSTRAP_TAR}" -C "${TMPDIR}"

    # take injected config bits and move them to state directories
    if [ -e "${TMPDIR}/ic_crypto" ]; then
        cp -r -T "${TMPDIR}/ic_crypto" "${STATE_ROOT}/crypto"
    fi
    for DIR in ic_registry_local_store nns_public_key.pem; do
        if [ -e "${TMPDIR}/${DIR}" ]; then
            cp -r -T "${TMPDIR}/${DIR}" "${STATE_ROOT}/data/${DIR}"
        fi
    done

    # stash a couple of things away to config store
    for FILE in journalbeat.conf network.conf nns.conf backup.conf; do
        if [ -e "${TMPDIR}/${FILE}" ]; then
            cp "${TMPDIR}/${FILE}" "${CONFIG_ROOT}/${FILE}"
        fi
    done
    for DIR in accounts_ssh_authorized_keys; do
        if [ -e "${TMPDIR}/${DIR}" ]; then
            cp -r "${TMPDIR}/${DIR}" "${CONFIG_ROOT}/${DIR}"
        fi
    done

    rm -rf "${TMPDIR}"
}

MAX_TRIES=10

while [ ! -f /boot/config/CONFIGURED ]; do
    DEV="$(find_removable_devices)"

    # Check whether we were provided with a removable device -- on "real"
    # VM deployments this will be the method used to inject bootstrap information
    # into the system.
    # But even if nothing can be mounted, just try and see if something usable
    # is there already -- this might be useful when operating this thing as a
    # docker container instead of full-blown VM.
    if [ "${DEV}" != "" ]; then
        mount -t vfat -o ro "${DEV}" /mnt
    fi

    if [ -e /mnt/ic-bootstrap.tar ]; then
        echo "Processing bootstrap config"
        process_bootstrap /mnt/ic-bootstrap.tar /boot/config /var/lib/ic
        touch /boot/config/CONFIGURED
    else
        MAX_TRIES=$(("${MAX_TRIES}" - 1))
        if [ "${MAX_TRIES}" == 0 ]; then
            echo "No registration configuration provided to bootstrap IC node -- continuing without"
            exit 1
        else
            echo "Retrying to find bootstrap config"
            sleep 1
        fi
    fi

    # Fix up permissions. This is actually the wrong place.
    chown ic-replica.nogroup -R /var/lib/ic/data

    if [ "${DEV}" != "" ]; then
        umount /mnt
    fi
done

# HACK: This workaround configures Journalbeat in mainnet. Will be removed once
#       applied to all guests.
if [ ! -f /boot/config/journalbeat.conf ]; then
    cat >/boot/config/journalbeat.conf <<EOF
journalbeat_hosts=elasticsearch.mercury.dfinity.systems:443
EOF
fi
