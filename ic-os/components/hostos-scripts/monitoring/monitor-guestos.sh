#!/bin/bash

set -e

# Monitor the GuestOS virtual machine.

# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename $0)[$$]"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Monitor GuestOS Virtual Machine

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

function monitor_guestos() {
    if [ ! "$(virsh list --all | grep 'guestos')" ]; then
        write_log "ERROR: GuestOS virtual machine is not defined."
        write_metric "hostos_guestos_state" \
            "1" \
            "GuestOS virtual machine state" \
            "gauge"
        exit 1
    fi

    if [ "$(virsh list --state-running | grep 'guestos')" ]; then
        write_metric "hostos_guestos_state" \
            "0" \
            "GuestOS virtual machine state" \
            "gauge"
    else
        write_log "GuestOS virtual machine is not running."
        write_metric "hostos_guestos_state" \
            "2" \
            "GuestOS virtual machine state" \
            "gauge"
    fi
}

function main() {
    # Establish run order
    monitor_guestos
}

main
