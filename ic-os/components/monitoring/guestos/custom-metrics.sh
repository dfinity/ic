#!/bin/bash

set -e

# Custom GuestOS metrics

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/config.sh

MICROCODE_FILE="/sys/devices/system/cpu/cpu0/microcode/version"
GUESTOS_VERSION_FILE="/opt/ic/share/version.txt"
STATE_ROOT_PATH="/var/lib/ic"

function update_guestos_version_metric() {
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

function update_guestos_boot_action_metric() {
    write_metric_attr "guestos_boot_action" \
        "{successful_boot=\"true\"}" \
        "0" \
        "GuestOS boot action" \
        "gauge"
}

function update_config_version_metric() {
    config_version=$(get_config_value '.config_version')
    write_log "Found GuestOS config version: ${config_version}"
    write_metric_attr "guestos_config_version" \
        "{version=\"${config_version}\"}" \
        "1" \
        "GuestOS config version" \
        "gauge"
}

function update_node_operator_private_key_metric() {
    node_operator_private_key_exists=0
    if [ -f "${STATE_ROOT_PATH}/data/node_operator_private_key.pem" ]; then
        node_operator_private_key_exists=1
    fi

    write_metric "guestos_node_operator_private_key_exists" \
        "${node_operator_private_key_exists}" \
        "Existence of a Node Operator private key indicates the node deployment method" \
        "gauge"
}

function main() {
    update_guestos_version_metric
    update_guestos_boot_action_metric
    update_config_version_metric
    update_node_operator_private_key_metric
}

main
