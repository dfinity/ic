#!/bin/bash

set -e

# Detect the first successful boot of HostOS.
# Successful boot is defined as a boot where GuestOS can be booted.
# This script is executed by HostOS right before booting GuestOS VM.

source /opt/ic/bin/logging.sh
# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename "$0")[$$]"
FIRST_BOOT_FILE="/boot/config/first_boot"
HOSTOS_VERSION_FILE="/opt/ic/share/version.txt"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Detect HostOS First Successful Boot

Arguments:
  -h, --help            show this help message and exit
'
            exit 1
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

function print_to_terminal() {
    local message=$1

    echo "${SCRIPT} ${message}" >/dev/tty1
}

function get_first_boot_state() {
    if [ -r ${FIRST_BOOT_FILE} ]; then
        FIRST_BOOT_STATE=$(cat ${FIRST_BOOT_FILE})
    else
        FIRST_BOOT_STATE=1
    fi
}

function write_first_boot_state() {
    echo "0" >${FIRST_BOOT_FILE}
}

function detect_first_boot() {
    get_first_boot_state

    if [ ${FIRST_BOOT_STATE} -eq 1 ]; then
        write_log "First boot detected."
        write_first_boot_state
        write_metric "hostos_first_boot_state" \
            "1" \
            "HostOS first boot state" \
            "gauge"
    else
        write_log "Not first boot, continuing with startup."
        write_metric "hostos_first_boot_state" \
            "0" \
            "HostOS first boot state" \
            "gauge"
    fi
    write_metric_attr "hostos_boot_action" \
        "{successful_boot=\"true\"}" \
        "0" \
        "HostOS boot action" \
        "gauge"
}

function get_hostos_version() {
    if [ -r ${HOSTOS_VERSION_FILE} ]; then
        HOSTOS_VERSION=$(cat ${HOSTOS_VERSION_FILE})
        HOSTOS_VERSION_OK=1
    else
        HOSTOS_VERSION="unknown"
        HOSTOS_VERSION_OK=0
    fi
    write_log "HostOS version ${HOSTOS_VERSION}"
    write_metric_attr "hostos_version" \
        "{version=\"${HOSTOS_VERSION}\"}" \
        "${HOSTOS_VERSION_OK}" \
        "HostOS version string" \
        "gauge"
}

function main() {
    # Establish run order
    get_hostos_version
    detect_first_boot
}

main
