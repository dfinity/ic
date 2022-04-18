#!/bin/bash

set -e

# Start the GuestOS virtual machine.

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Start GuestOS virtual machine

Arguments:
  -c=, --config=        specify the GuestOS configuration file (Default: /var/lib/libvirt/guestos.xml)
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

# Set arguments if undefined
CONFIG="${CONFIG:=/var/lib/libvirt/guestos.xml}"

write_log() {
    local message=$1

    if [ -t 1 ]; then
        echo "${SCRIPT} ${message}" >/dev/stdout
    fi

    logger -t ${SCRIPT} "${message}"
}

write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    echo -e "# HELP ${name} ${help}\n# TYPE ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}

function define_guestos() {
    if [ "$(virsh list --all | grep 'guestos')" ]; then
        write_log "GuestOS virtual machine is already defined."
        write_metric "hostos_guestos_service_define" \
            "0" \
            "GuestOS virtual machine define state" \
            "gauge"
    else
        virsh define ${CONFIG}
        write_log "Defining GuestOS virtual machine."
        write_metric "hostos_guestos_service_define" \
            "1" \
            "GuestOS virtual machine define state" \
            "gauge"
    fi
}

function start_guestos() {
    if [ "$(virsh list --state-running | grep 'guestos')" ]; then
        write_log "GuestOS virtual machine is already running."
        write_metric "hostos_guestos_service_start" \
            "0" \
            "GuestOS virtual machine start state" \
            "gauge"
    else
        virsh start guestos
        write_log "Starting GuestOS virtual machine."
        write_metric "hostos_guestos_service_start" \
            "1" \
            "GuestOS virtual machine start state" \
            "gauge"
    fi
}

function enable_guestos() {
    if [ "$(virsh list --autostart | grep 'guestos')" ]; then
        write_log "GuestOS virtual machine is already enabled."
        write_metric "hostos_guestos_service_enable" \
            "0" \
            "GuestOS virtual machine enable state" \
            "gauge"
    else
        virsh autostart guestos
        write_log "Enabling GuestOS virtual machine."
        write_metric "hostos_guestos_service_enable" \
            "1" \
            "GuestOS virtual machine enable state" \
            "gauge"
    fi
}

function main() {
    # Establish run order
    define_guestos
    start_guestos
    enable_guestos
}

main
