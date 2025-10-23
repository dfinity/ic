#!/bin/bash

# Initialize configuration in /run/config from bootstrap package.

set -eo pipefail

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename $0)[$$]"

# Process config.json from bootstrap package
# Arguments:
# - $1: path to the bootstrap package (typically /mnt/config/ic-bootstrap.tar)
# - $2: path to config space (typically /run/config)
function process_config_json() {
    local BOOTSTRAP_TAR="$1"
    local CONFIG_ROOT="$2"

    local TMPDIR=$(mktemp -d)
    tar xf "${BOOTSTRAP_TAR}" -C "${TMPDIR}"

    # Create config directory if it doesn't exist
    mkdir -p "${CONFIG_ROOT}"

    if [ -e "${TMPDIR}/config.json" ]; then
        echo "Setting up config.json"
        cp "${TMPDIR}/config.json" "${CONFIG_ROOT}/config.json"
        chown ic-replica:nogroup "${CONFIG_ROOT}/config.json"
    fi

    rm -rf "${TMPDIR}"
}

# Check if CONFIG device is mounted and has bootstrap config
if [ -e /mnt/config/ic-bootstrap.tar ]; then
    echo "Processing config initialization from /mnt/config/ic-bootstrap.tar"
    process_config_json /mnt/config/ic-bootstrap.tar /run/config
    echo "Successfully processed config initialization"
else
    echo "No bootstrap config available at /mnt/config/ic-bootstrap.tar"
    exit 1
fi

# Create file under /run/config/guest_vm_type, this can be used to add ConditionPathExists conditions to systemd units
guest_vm_type="$(jq -r ".guest_vm_type" /run/config/config.json)"
if [[ "$guest_vm_type" = null ]]; then
    guest_vm_type=default
fi
mkdir -p "/run/config/guest_vm_type"
touch "/run/config/guest_vm_type/$guest_vm_type"
