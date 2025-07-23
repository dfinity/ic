#!/bin/bash

set -e

# Custom GuestOS metrics

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/config.sh

MICROCODE_FILE="/sys/devices/system/cpu/cpu0/microcode/version"

function update_config_version_metric() {
    config_version=$(get_config_value '.config_version')
    write_log "Found GuestOS config version: ${config_version}"
    write_metric_attr "guestos_config_version" \
        "{version=\"${config_version}\"}" \
        "1" \
        "GuestOS config version" \
        "gauge"
}

function main() {
    update_config_version_metric
}

main
