#!/bin/bash

set -e

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

GRUB_CONFIG_FILE="/boot/grub/grub.cfg"
GRUB_FOLDER="/boot/grub"

function update_grub_config_version_metric() {
    if [[ ! -r "${GRUB_CONFIG_FILE}" ]]; then
        write_log "ERROR: Cannot read grub config file: ${GRUB_CONFIG_FILE}"
        return 1
    fi

    grub_config_hash=$(sha256sum "${GRUB_CONFIG_FILE}" | cut -d' ' -f1)
    write_log "Found grub config hash: ${grub_config_hash}"
    write_metric_attr "grub_config_version" \
        "{version=\"${grub_config_hash}\"}" \
        "1" \
        "Grub config file version hash" \
        "gauge"
}

function update_grub_version_metric() {
    if [[ ! -d "${GRUB_FOLDER}" ]]; then
        write_log "ERROR: Cannot access grub folder: ${GRUB_FOLDER}"
        return 1
    fi

    grub_folder_hash=$(find "${GRUB_FOLDER}" -type f -exec sha256sum {} \; | sort | sha256sum | cut -d' ' -f1)
    write_log "Found grub folder hash: ${grub_folder_hash}"
    write_metric_attr "grub_version" \
        "{version=\"${grub_folder_hash}\"}" \
        "1" \
        "Grub folder contents version hash" \
        "gauge"
}

function main() {
    update_grub_config_version_metric
    update_grub_version_metric
}

main
