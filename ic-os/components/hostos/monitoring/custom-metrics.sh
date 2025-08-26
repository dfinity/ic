#!/bin/bash

set -e

# Custom HostOS metrics

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/config.sh

MICROCODE_FILE="/sys/devices/system/cpu/cpu0/microcode/version"

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
    config_version=$(get_config_value '.config_version')
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
