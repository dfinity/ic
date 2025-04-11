#!/bin/bash

set -e

# Custom HostOS metrics

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

MICROCODE_FILE="/sys/devices/system/cpu/cpu0/microcode/version"
HOSTOS_CONFIG_FILE="/boot/config/config.json"

function update_microcode_metric() {
    if [[ ! -r "${MICROCODE_FILE}" ]]; then
        write_log "ERROR: Cannot read microcode version file: ${MICROCODE_FILE}"
        return 1
    fi

    microcode=$(tr -d '\n' <"${MICROCODE_FILE}")
    write_log "Found microcode version: ${microcode}"
    write_metric_attr "node_cpu_microcode" \
        "{version=\"${microcode}\"}" \
        "1" \
        "CPU microcode version" \
        "gauge"
}

function update_config_version_metric() {
    if [[ ! -r "${HOSTOS_CONFIG_FILE}" ]]; then
        write_log "ERROR: Cannot read HostOS config object file: ${HOSTOS_CONFIG_FILE}"
        return 1
    fi

    config_version=$(jq -r '.config_version' ${HOSTOS_CONFIG_FILE})
    write_log "Found HostOS config version: ${config_version}"
    write_metric_attr "hostos_config_version" \
        "{version=\"${config_version}\"}" \
        "1" \
        "HostOS config version" \
        "gauge"

}

function main() {
    update_microcode_metric
    update_config_version_metric
}

main
