#!/bin/bash

set -e

# Detect the first boot of GuestOS virtual machine.

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"
FIRST_BOOT_FILE="/boot/config/first_boot"
HOSTOS_VERSION_FILE="/opt/ic/share/version.txt"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Detect GuestOS Virtual Machine First Boot

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

write_log() {
    local message=$1

    if [ -t 1 ]; then
        echo "${SCRIPT} ${message}" >/dev/stdout
    fi

    logger -t ${SCRIPT} "${message}"
}

write_metric_attr() {
    local name=$1
    local attr=$2
    local value=$3
    local help=$4
    local type=$5

    echo -e "# HELP ${name} ${help}\n# TYPE ${type}\n${name}${attr} ${value}" >"${METRICS_DIR}/${name}.prom"
}

write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    echo -e "# HELP ${name} ${help}\n# TYPE ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}

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
        write_metric "hostos_guestos_first_boot_state" \
            "1" \
            "GuestOS virtual machine first boot" \
            "gauge"
    else
        write_log "Not first boot, continuing with startup."
        write_metric "hostos_guestos_first_boot_state" \
            "0" \
            "GuestOS virtual machine first boot state" \
            "gauge"
    fi
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
