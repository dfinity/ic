#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

CONFIG="${CONFIG:=/var/ic/config/config.ini}"

function parse_args() {
    if [ $# -ne 1 ]; then
        echo "Usage: $0 <SetupOS|HostOS>"
        exit 1
    fi
    NODE_TYPE="$1"
    if [ "$NODE_TYPE" != "SetupOS" ] && [ "$NODE_TYPE" != "HostOS" ]; then
        echo "Invalid node type: $NODE_TYPE"
        exit 1
    fi
}

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_prefix") IPV6_GATEWAY="${value}" ;;
        esac
    done <"${CONFIG}"
}

function generate_addresses() {
    if [ "$NODE_TYPE" = "SetupOS" ]; then
        MAC_ADDR=$(/opt/ic/bin/setupos_tool generate-mac-address --node-type SetupOS)
        IPV6_ADDR=$(/opt/ic/bin/setupos_tool generate-ipv6-address --node-type SetupOS)
    else
        MAC_ADDR=$(/opt/ic/bin/hostos_tool generate-mac-address --node-type HostOS)
        IPV6_ADDR=$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type HostOS)
    fi
    echo "Generated MAC address: $MAC_ADDR"
    echo "Generated IPv6 address: $IPV6_ADDR"
}

function select_fastest_interface() {
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')
    BEST_IFACE=""
    BEST_SPEED=0

    for IFACE in $INTERFACES; do
        if ip -6 addr show dev "$IFACE" 2>/dev/null | grep -q "inet6 fe80::"; then
            SPEED_STR=$(ethtool "$IFACE" 2>/dev/null | grep "Speed:" || true)
            SPEED=$(echo "$SPEED_STR" | grep -oP '\d+' || echo 0)
            if [ "${SPEED:-0}" -gt "$BEST_SPEED" ]; then
                BEST_SPEED=$SPEED
                BEST_IFACE="$IFACE"
            fi
        fi
    done

    if [ -z "$BEST_IFACE" ]; then
        echo "No suitable interface found with IPv6 connectivity."
        exit 1
    fi
    echo "Using fastest interface: $BEST_IFACE at ${BEST_SPEED}Mb/s"
}

function configure_netplan() {
    local NETPLAN_TEMPLATE="/opt/ic/share/99-setup.yaml.template"
    local NETPLAN_OUTPUT="/opt/ic/share/99-setup.yaml"

    cp "$NETPLAN_TEMPLATE" "$NETPLAN_OUTPUT"
    sed -i "s|{IFACE}|$BEST_IFACE|g" "$NETPLAN_OUTPUT"
    sed -i "s|{MAC_ADDRESS}|$MAC_ADDR|g" "$NETPLAN_OUTPUT"
    sed -i "s|{IPV6_ADDR}|$IPV6_ADDR|g" "$NETPLAN_OUTPUT"
    sed -i "s|{IPV6_GATEWAY}|$IPV6_GATEWAY|g" "$NETPLAN_OUTPUT"

    echo "Netplan configuration written to $NETPLAN_OUTPUT"
    echo "Applying netplan..."
    netplan generate
    netplan apply
    echo "Network configuration applied successfully for $NODE_TYPE."
}

function main() {
    log_start "$(basename $0)"
    parse_args "$@"
    read_variables
    generate_addresses
    select_fastest_interface
    configure_netplan
    log_end "$(basename $0)"
}

main "$@"
