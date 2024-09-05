#!/bin/bash

set -e

# Fetch the management MAC address of the physical machine.

source /opt/ic/bin/logging.sh
# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename $0)[$$]"

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
    fetch_mgmt_mac
}

main
