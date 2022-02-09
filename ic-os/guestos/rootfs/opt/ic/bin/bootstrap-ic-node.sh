#!/bin/bash

# Provision a node based on an injected "ic-bootstrap.tar" file. This script
# is meant to be run as a prerequisite before launching orchestrator/replica.
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
        echo "Consider device $DEV" >&2
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
                if blockdev "${TGT}"; then
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
        echo "Installing initial crypto material"
        cp -r -T "${TMPDIR}/ic_crypto" "${STATE_ROOT}/crypto"
    fi
    for DIR in ic_registry_local_store nns_public_key.pem; do
        if [ -e "${TMPDIR}/${DIR}" ]; then
            echo "Setting up initial ${DIR}"
            cp -r -T "${TMPDIR}/${DIR}" "${STATE_ROOT}/data/${DIR}"
        fi
    done

    # stash the following configuration files to config store
    # note: keep this list in sync with configurations supported in build-bootstrap-config-image.sh
    for FILE in journalbeat.conf network.conf nns.conf backup.conf log.conf malicious_behavior.conf; do
        if [ -e "${TMPDIR}/${FILE}" ]; then
            echo "Setting up ${FILE}"
            cp "${TMPDIR}/${FILE}" "${CONFIG_ROOT}/${FILE}"
        fi
    done
    for DIR in accounts_ssh_authorized_keys; do
        if [ -e "${TMPDIR}/${DIR}" ]; then
            echo "Setting up accounts_ssh_authorized_keys"
            cp -r "${TMPDIR}/${DIR}" "${CONFIG_ROOT}/${DIR}"
        fi
    done

    rm -rf "${TMPDIR}"

    # Synchronize the above cached writes to persistent storage
    # to make sure the system can boot successfully after a hard shutdown.
    sync
}

MAX_TRIES=10

if [ -f /boot/config/CONFIGURED ]; then
    echo "Bootstrap completed already"
    exit 0
fi

while [ ! -f /boot/config/CONFIGURED ]; do
    echo "Locating removable device"
    DEV="$(find_removable_devices)"

    # Check whether we were provided with a removable device -- on "real"
    # VM deployments this will be the method used to inject bootstrap information
    # into the system.
    # But even if nothing can be mounted, just try and see if something usable
    # is there already -- this might be useful when operating this thing as a
    # docker container instead of full-blown VM.
    if [ "${DEV}" != "" ]; then
        echo "Found removable device at ${DEV}"
        mount -t vfat -o ro "${DEV}" /mnt
    fi

    if [ -e /mnt/ic-bootstrap.tar ]; then
        echo "Processing bootstrap config"
        process_bootstrap /mnt/ic-bootstrap.tar /boot/config /var/lib/ic
        echo "Successfully processed bootstrap config"
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
