#!/bin/bash

set -e

# Custom HostOS metrics

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

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

function main() {
    update_microcode_metric
}

main
