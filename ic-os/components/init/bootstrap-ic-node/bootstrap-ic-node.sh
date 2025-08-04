#!/bin/bash

# Provision a node based on an injected "ic-bootstrap.tar" file. This script
# is meant to be run as a prerequisite before launching orchestrator/replica.
#
# The tar file can be supplied using one of two methods:
# - as "ic-bootstrap.tar" stored on a (virtual) removable media attached
#   on first boot
# - it can be directly "pushed" into the filesystem as /mnt/ic-bootstrap.tar
#   (e.g. bind mount when running the entire stack as docker container)

set -eo pipefail

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename $0)[$$]"
GUESTOS_VERSION_FILE="/opt/ic/share/version.txt"

function get_guestos_version() {
    if [ -r ${GUESTOS_VERSION_FILE} ]; then
        GUESTOS_VERSION=$(cat ${GUESTOS_VERSION_FILE})
        GUESTOS_VERSION_OK=1
    else
        GUESTOS_VERSION="unknown"
        GUESTOS_VERSION_OK=0
    fi
    write_log "GuestOS version ${GUESTOS_VERSION}"
    write_metric_attr "guestos_version" \
        "{version=\"${GUESTOS_VERSION}\"}" \
        "${GUESTOS_VERSION_OK}" \
        "GuestOS version string" \
        "gauge"
}

# List all block devices that could potentially contain the ic-bootstrap.tar configuration,
# i.e. "removable" devices, devices with the serial "config"
# or devices containing a filesystem with the label "CONFIG".
function find_config_devices() {
    for DEV in $(ls -C /sys/class/block); do
        echo "Consider device $DEV" >&2
        if [ -e /sys/class/block/"${DEV}"/removable ]; then
            # In production, a removable device is used to pass configuration
            # into the VM.
            # In some test environments where this is not available, the
            # configuration device is identified by the serial "config".
            local IS_REMOVABLE=$(cat /sys/class/block/"${DEV}"/removable)
            local CONFIG_SERIAL=$(udevadm info --name=/dev/"${DEV}" | grep "ID_SCSI_SERIAL=config")
            local FS_LABEL=$(lsblk --fs --noheadings --output LABEL /dev/"${DEV}")
            if [ "${IS_REMOVABLE}" == 1 ] || [ "${CONFIG_SERIAL}" != "" ] || [ "${FS_LABEL}" == "CONFIG" ]; then
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
# both config space and parts of /var/lib/ic/data and /var/lib/ic/crypto
# note: keep this list in sync with configurations supported in `config::guestos_bootstrap_image`.
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
        cp -rL -T "${TMPDIR}/ic_crypto" "${STATE_ROOT}/crypto"
    fi
    if [ -e "${TMPDIR}/ic_state" ]; then
        echo "Installing initial state"
        cp -rL -T "${TMPDIR}/ic_state" "${STATE_ROOT}/data/ic_state"
    fi
    if [ -e "${TMPDIR}/ic_registry_local_store" ]; then
        echo "Setting up initial ic_registry_local_store"
        cp -rL -T "${TMPDIR}/ic_registry_local_store" "${STATE_ROOT}/data/ic_registry_local_store"
    fi

    if [ -e "${TMPDIR}/node_operator_private_key.pem" ]; then
        echo "Setting up initial node_operator_private_key.pem"
        cp -rL -T "${TMPDIR}/node_operator_private_key.pem" "${STATE_ROOT}/data/node_operator_private_key.pem"
        chmod 400 "${STATE_ROOT}/data/node_operator_private_key.pem"
    fi

    VARIANT_TYPE=$(/opt/ic/bin/config check-variant-type)
    NNS_KEY_DEST="${STATE_ROOT}/data/nns_public_key.pem"
    if [ "${VARIANT_TYPE}" = "dev" ] && [ -e "${TMPDIR}/nns_public_key_override.pem" ]; then
        echo "Overriding nns_public_key.pem with nns_public_key_override.pem from injected config"
        cp -rL -T "${TMPDIR}/nns_public_key_override.pem" "${NNS_KEY_DEST}"
        chmod 444 "${STATE_ROOT}/data/nns_public_key.pem"
    elif [ "${VARIANT_TYPE}" = "prod" ] && [ -e "/opt/ic/share/nns_public_key.pem" ]; then
        echo "Copying nns_public_key.pem from /opt/ic/share/nns_public_key.pem"
        cp -rL -T "/opt/ic/share/nns_public_key.pem" "${NNS_KEY_DEST}"
        chmod 444 "${STATE_ROOT}/data/nns_public_key.pem"
    fi

    for DIR in accounts_ssh_authorized_keys; do
        if [ -e "${TMPDIR}/${DIR}" ]; then
            echo "Setting up accounts_ssh_authorized_keys"
            cp -rL "${TMPDIR}/${DIR}" "${CONFIG_ROOT}/${DIR}"
        fi
    done

    rm -rf "${TMPDIR}"

    # Fix up permissions. Ideally this is specific to only what is copied. If
    # we do make this change, we need to make sure `data` itself has the
    # correct permissions.
    chown ic-replica:nogroup -R "${STATE_ROOT}/data"

    # Synchronize the above cached writes to persistent storage
    # to make sure the system can boot successfully after a hard shutdown.
    sync
}

# Process config.json from bootstrap package
# Arguments:
# - $1: path to the bootstrap package (typically /mnt/ic-bootstrap.tar)
# - $2: path to config space (typically /boot/config)
function process_config_json() {
    local BOOTSTRAP_TAR="$1"
    local CONFIG_ROOT="$2"

    local TMPDIR=$(mktemp -d)
    tar xf "${BOOTSTRAP_TAR}" -C "${TMPDIR}"

    if [ -e "${TMPDIR}/config.json" ]; then
        echo "Setting up config.json"
        cp "${TMPDIR}/config.json" "${CONFIG_ROOT}/config.json"
        chown ic-replica:nogroup "${CONFIG_ROOT}/config.json"
    fi

    rm -rf "${TMPDIR}"
}

MAX_TRIES=10

get_guestos_version

write_metric_attr "guestos_boot_action" \
    "{successful_boot=\"true\"}" \
    "0" \
    "GuestOS boot action" \
    "gauge"

# /boot/config/CONFIGURED serves as a tag to indicate that the one-time bootstrap configuration has been completed.
# If the `/boot/config/CONFIGURED` file is not present, the boot sequence will
# search for a virtual USB stick (the bootstrap config image)
# containing the injected configuration files, and create the file.
if [ -f /boot/config/CONFIGURED ]; then
    echo "Bootstrap completed already"
fi

while [ ! -f /boot/config/CONFIGURED ]; do
    echo "Locating CONFIG device"
    DEV="$(find_config_devices)"

    # Check whether we were provided with a CONFIG device -- on "real"
    # VM deployments this will be the method used to inject bootstrap information
    # into the system.
    # But even if nothing can be mounted, just try and see if something usable
    # is there already -- this might be useful when operating this thing as a
    # docker container instead of full-blown VM.
    if [ "${DEV}" != "" ]; then
        echo "Found CONFIG device at ${DEV}"
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

    if [ "${DEV}" != "" ]; then
        umount /mnt
    fi
done

# Process config.json every boot (not just on first bootstrap)
# Even if nothing can be mounted, just try and see if something usable
# is there already -- this might be useful when operating this thing as a
# docker container instead of full-blown VM.
echo "Checking for config.json updates"
DEV="$(find_config_devices)"
if [ "${DEV}" != "" ]; then
    echo "Found CONFIG device at ${DEV}"
    mount -t vfat -o ro "${DEV}" /mnt
    process_config_json /mnt/ic-bootstrap.tar /boot/config
fi

if [ -e /mnt/ic-bootstrap.tar ]; then
    echo "Processing config.json from pre-mounted bootstrap"
    process_config_json /mnt/ic-bootstrap.tar /boot/config
fi

if [ "${DEV}" != "" ]; then
    umount /mnt
fi

# Write metric on use of node_operator_private_key
node_operator_private_key_exists=0
if [ -f "/var/lib/ic/data/node_operator_private_key.pem" ]; then
    node_operator_private_key_exists=1
fi

write_metric "guestos_node_operator_private_key_exists" \
    "${node_operator_private_key_exists}" \
    "Existence of a Node Operator private key indicates the node deployment method" \
    "gauge"
