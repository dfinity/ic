#!/bin/bash

set -e

# Fetch the management MAC address of the physical machine.

SCRIPT="$(basename $0)[$$]"
CONFIG="/boot/config/config.ini"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Fetch Management MAC Address

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

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "mgmt_mac") mgmt_mac="${value}" ;;
        esac
    done <"${CONFIG}"
}

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

# Fetch the management MAC address of the physical machine.
# The management MAC address will be used as unique key for:
#  - Hostnames
#  - IPv6 addresses
function fetch_mgmt_mac() {
    MAC=$(ipmitool lan print | sed -e 's/^MAC Address.*\([0-9a-f:]\{17\}\)/\1/' -e t -e d)

    if [ "${MAC}" == "" ]; then
        write_log "ERROR: Unable to determine MAC address."
        write_metric "hostos_fetch_mgmt_mac" \
            "1" \
            "HostOS fetch management MAC address" \
            "gauge"
        exit 1
    else
        write_log "Unique management MAC address is: ${MAC}"
        write_metric "hostos_fetch_mgmt_mac" \
            "0" \
            "HostOS fetch management MAC address" \
            "gauge"
    fi

    echo "${MAC}"
}

function main() {
    # Establish run order
    read_variables
    if [ "${mgmt_mac}" == "" ]; then
        fetch_mgmt_mac
    else
        echo "${mgmt_mac}"
    fi
}

main
