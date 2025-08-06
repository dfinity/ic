#!/bin/bash

# Provision a node based on an injected "ic-bootstrap.tar" file. This script
# is meant to be run as a prerequisite before launching orchestrator/replica.
#
# The tar file can be supplied as "ic-bootstrap.tar" stored on a (virtual) removable
# media (mounted at /mnt/config by mount-config.sh)

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

# Process the bootstrap package to populate SSH keys, /var/lib/ic/data and /var/lib/ic/crypto
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

    if [ -e "${TMPDIR}/nns_public_key.pem" ]; then
        echo "Setting up initial nns_public_key.pem"
        cp -rL -T "${TMPDIR}/nns_public_key.pem" "${STATE_ROOT}/data/nns_public_key.pem"
        chmod 444 "${STATE_ROOT}/data/nns_public_key.pem"
    fi

    if [ -e "${TMPDIR}/node_operator_private_key.pem" ]; then
        echo "Setting up initial node_operator_private_key.pem"
        cp -rL -T "${TMPDIR}/node_operator_private_key.pem" "${STATE_ROOT}/data/node_operator_private_key.pem"
        chmod 400 "${STATE_ROOT}/data/node_operator_private_key.pem"
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

if [ ! -f /boot/config/CONFIGURED ]; then
    echo "Checking for bootstrap configuration"

    if [ -e /mnt/config/ic-bootstrap.tar ]; then
        echo "Processing bootstrap data from /mnt/config"
        process_bootstrap /mnt/config/ic-bootstrap.tar /boot/config /var/lib/ic
        echo "Successfully processed bootstrap data"
        touch /boot/config/CONFIGURED
    else
        echo "No registration configuration provided to bootstrap IC node"
        exit 1
    fi
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
