#!/bin/bash

set -e

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

GRUB_CONFIG_FILE="/boot/grub/grub.cfg"
BOOTX64_EFI_FILE="/boot/efi/EFI/Boot/bootx64.efi"

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
    if [[ ! -r "${BOOTX64_EFI_FILE}" ]]; then
        write_log "ERROR: Cannot read bootx64.efi file: ${BOOTX64_EFI_FILE}"
        return 1
    fi

    grub_bootx64_hash=$(sha256sum "${BOOTX64_EFI_FILE}" | cut -d' ' -f1)
    write_log "Found bootx64.efi hash: ${grub_bootx64_hash}"
    write_metric_attr "grub_efi_version" \
        "{version=\"${grub_bootx64_hash}\"}" \
        "1" \
        "Bootx64.efi file version hash" \
        "gauge"
}

function main() {
    update_grub_config_version_metric
    update_grub_version_metric
}

main
