#!/bin/bash

# Get address of interface
#
# Arguments:
# - $1: address family (4 or 6 for IPv4 or IPv6)
# - $2: interface name
function get_if_address() {
    local FAMILY=-"$1"
    local INTERFACE="$2"
    ip -o "${FAMILY}" addr show up primary scope global "${INTERFACE}" | while read -r num dev family addr options; do
        echo ${addr%/*}
        break
    done
}

# Get address of interface
#
# Arguments:
# - $1: address family (4 or 6 for IPv4 or IPv6)
# - $2: interface name
function check_retry_interface_config() {
    local FAMILY=-"$1"
    local INTERFACE="$2"
    local ADDR=$(get_if_address "${FAMILY}" "${INTERFACE}")

    if [ "${ADDR}" == "" ]; then
        echo "Interface ${INTERFACE} not configured properly, forcing reconfiguration"
        networkctl reconfigure "${INTERFACE}"
    fi
}

while true; do
    check_retry_interface_config 6 enp1s0
    sleep 10
done
