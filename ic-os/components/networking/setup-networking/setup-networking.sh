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
            "ipv6_gateway") IPV6_GATEWAY="${value}" ;;
        esac
    done <"${CONFIG}"

    if [ -z "$IPV6_GATEWAY" ]; then
        echo "No IPv6 gateway found in $CONFIG."
        exit 1
    fi
}

function generate_addresses() {
    echo "Generating MAC and IPv6 addresses..."
    if [ "$NODE_TYPE" = "SetupOS" ]; then
        MAC_ADDR=$(/opt/ic/bin/setupos_tool generate-mac-address --node-type SetupOS)
        IPV6_ADDR=$(/opt/ic/bin/setupos_tool generate-ipv6-address --node-type SetupOS)
    else
        MAC_ADDR=$(/opt/ic/bin/hostos_tool generate-mac-address --node-type HostOS)
        IPV6_ADDR=$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type HostOS)
    fi

    if [ -z "$MAC_ADDR" ] || [ -z "$IPV6_ADDR" ]; then
        echo "Failed to generate MAC or IPv6 address."
        exit 1
    fi

    echo "Generated MAC address: $MAC_ADDR"
    echo "Generated IPv6 address: $IPV6_ADDR"
}

function gather_interfaces_by_speed() {
    echo "Gathering and sorting interfaces by speed..."
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$')
    declare -A SPEED_MAP

    for IFACE in $INTERFACES; do
        SPEED_STR=$(ethtool "$IFACE" 2>/dev/null | grep "Speed:" || true)
        SPEED=$(echo "$SPEED_STR" | grep -Eo '[0-9]+' || echo 0)
        SPEED_MAP["$IFACE"]=$SPEED
    done

    # Sort interfaces by speed descending
    SORTED_INTERFACES=$(for IFACE in "${!SPEED_MAP[@]}"; do
        echo "${SPEED_MAP[$IFACE]} $IFACE"
    done | sort -nrk1 | awk '{print $2}')

    if [ -z "$SORTED_INTERFACES" ]; then
        echo "No interfaces found."
        exit 1
    fi

    INTERFACE_LIST=$(echo "$SORTED_INTERFACES" | paste -sd, -)
}

function configure_netplan() {
    echo "Configuring netplan..."
    local NETPLAN_TEMPLATE="/opt/ic/share/99-setup.yaml.template"
    local NETPLAN_OUTPUT="/run/netplan/99-setup.yaml"

    mkdir -p /run/netplan
    cp "$NETPLAN_TEMPLATE" "$NETPLAN_OUTPUT"

    sed -i "s|{INTERFACES}|$INTERFACE_LIST|g" "$NETPLAN_OUTPUT"
    sed -i "s|{MAC_ADDRESS}|$MAC_ADDR|g" "$NETPLAN_OUTPUT"
    sed -i "s|{IPV6_ADDR}|$IPV6_ADDR|g" "$NETPLAN_OUTPUT"
    sed -i "s|{IPV6_GATEWAY}|$IPV6_GATEWAY|g" "$NETPLAN_OUTPUT"

    # Dynamically add ethernets for each interface
    for IFACE in ${SORTED_INTERFACES}; do
        sed -i "/^  ethernets:/a \ \ \ \ $IFACE:\n      mtu: 1500\n      optional: true\n      lldp:\n        send: yes\n" "$NETPLAN_OUTPUT"
    done

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
    gather_interfaces_by_speed
    configure_netplan
    log_end "$(basename $0)"
}

main "$@"
