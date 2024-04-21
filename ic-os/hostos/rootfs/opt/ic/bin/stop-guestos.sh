#!/bin/bash

set -e

# Stop the GuestOS virtual machine.

# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename $0)[$$]"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Stop GuestOS virtual machine

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

function stop_guestos() {
    if [ "$(virsh list --state-shutoff | grep 'guestos')" ]; then
        write_log "GuestOS virtual machine is already stopped."
        write_metric "hostos_guestos_service_stop" \
            "0" \
            "GuestOS virtual machine stop state" \
            "gauge"
    else
        virsh destroy --graceful guestos
        write_log "Stopping GuestOS virtual machine."
        write_metric "hostos_guestos_service_stop" \
            "1" \
            "GuestOS virtual machine stop state" \
            "gauge"
    fi
}

function disable_guestos() {
    if [ "$(virsh list --autostart | grep 'guestos')" ]; then
        virsh autostart --disable guestos
        write_log "Disabling GuestOS virtual machine."
        write_metric "hostos_guestos_service_disable" \
            "1" \
            "GuestOS virtual machine disable state" \
            "gauge"
    else
        write_log "GuestOS virtual machine is already disabled."
        write_metric "hostos_guestos_service_disable" \
            "0" \
            "GuestOS virtual machine disable state" \
            "gauge"
    fi
}

function main() {
    # Establish run order
    stop_guestos
    disable_guestos
}

main
