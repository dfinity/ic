#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

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

    # Allow overriding config paths via environment variables
    if [ "$NODE_TYPE" = "SetupOS" ]; then
        CONFIG_BASE_PATH="${CONFIG_BASE_PATH:-/var/ic/config}"
    else
        CONFIG_BASE_PATH="${CONFIG_BASE_PATH:-/boot/config}"
    fi

    CONFIG="${CONFIG_BASE_PATH}/config.ini"
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
    IC_BIN_PATH="${IC_BIN_PATH:-/opt/ic/bin}"

    if [ "$NODE_TYPE" = "SetupOS" ]; then
        MAC_ADDR=$("${IC_BIN_PATH}/setupos_tool" generate-mac-address --node-type SetupOS)
        IPV6_ADDR=$("${IC_BIN_PATH}/setupos_tool" generate-ipv6-address --node-type SetupOS)
    else
        MAC_ADDR=$("${IC_BIN_PATH}/hostos_tool" generate-mac-address --node-type HostOS)
        IPV6_ADDR=$("${IC_BIN_PATH}/hostos_tool" generate-ipv6-address --node-type HostOS)
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
    echo "Interfaces sorted by speed: $INTERFACE_LIST"
}

function configure_netplan() {
    echo "Configuring netplan..."
    NETPLAN_TEMPLATE_PATH="${NETPLAN_TEMPLATE_PATH:-/opt/ic/share}"
    NETPLAN_TEMPLATE="${NETPLAN_TEMPLATE_PATH}/99-setup-netplan.yaml.template"
    
    NETPLAN_RUN_PATH="${NETPLAN_RUN_PATH:-/run/netplan}"
    NETPLAN_OUTPUT="${NETPLAN_RUN_PATH}/99-setup-netplan.yaml"

    mkdir -p "$NETPLAN_RUN_PATH"
    cp "$NETPLAN_TEMPLATE" "$NETPLAN_OUTPUT"

    sed -i "s|{INTERFACES}|${INTERFACE_LIST}|g" "$NETPLAN_OUTPUT"
    sed -i "s|{MAC_ADDRESS}|${MAC_ADDR}|g" "$NETPLAN_OUTPUT"
    sed -i "s|{IPV6_ADDR}|${IPV6_ADDR}|g" "$NETPLAN_OUTPUT"
    sed -i "s|{IPV6_GATEWAY}|${IPV6_GATEWAY}|g" "$NETPLAN_OUTPUT"

    # Dynamically add ethernets for each interface in descending speed
    for IFACE in ${SORTED_INTERFACES}; do
        sed -i "/^  ethernets:/a \ \ \ \ $IFACE:\n      mtu: 1500\n      optional: true\n      emit-lldp: true\n" "$NETPLAN_OUTPUT"
    done

    # Fix netplan configuration file permissions to silence warnings
    chmod 0600 "$NETPLAN_OUTPUT"

    echo "Netplan configuration written to $NETPLAN_OUTPUT"
    echo "Applying netplan..."
    netplan generate
    netplan apply
    echo "Network configuration applied successfully for $NODE_TYPE."
}

function main() {
    parse_args "$@"
    read_variables
    generate_addresses
    gather_interfaces_by_speed
    configure_netplan
}

if [ "$0" = "$BASH_SOURCE" ]; then
    main "$@"
fi
