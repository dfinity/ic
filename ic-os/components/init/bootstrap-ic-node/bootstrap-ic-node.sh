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

BOOTSTRAP_TAR_PATH="/mnt/config/ic-bootstrap.tar"
CONFIG_ROOT_PATH="/boot/config"
STATE_ROOT_PATH="/var/lib/ic"

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

# ${CONFIG_ROOT_PATH}/CONFIGURED serves as a tag to indicate that the one-time bootstrap configuration has been completed.
# If the `CONFIGURED` file is not present, the boot sequence will
# search for a virtual USB stick (the bootstrap config image)
# containing the injected configuration files, and create the file.
if [ -f ${CONFIG_ROOT_PATH}/CONFIGURED ]; then
    echo "Bootstrap completed already"
fi

if [ ! -f ${CONFIG_ROOT_PATH}/CONFIGURED ]; then
    echo "Checking for bootstrap configuration"

    if [ -e ${BOOTSTRAP_TAR_PATH} ]; then
        echo "Processing bootstrap data from /mnt/config"
        process_bootstrap ${BOOTSTRAP_TAR_PATH} ${CONFIG_ROOT_PATH} ${STATE_ROOT_PATH}
        echo "Successfully processed bootstrap data"
        touch ${CONFIG_ROOT_PATH}/CONFIGURED
    else
        echo "No registration configuration provided to bootstrap IC node"
        exit 1
    fi
fi

# Write metric on use of node_operator_private_key
node_operator_private_key_exists=0
if [ -f "${STATE_ROOT_PATH}/data/node_operator_private_key.pem" ]; then
    node_operator_private_key_exists=1
fi

write_metric "guestos_node_operator_private_key_exists" \
    "${node_operator_private_key_exists}" \
    "Existence of a Node Operator private key indicates the node deployment method" \
    "gauge"
