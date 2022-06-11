#!/bin/bash

set -e

# Generate the network configuration.

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -c=* | --config=*)
            CONFIG="${argument#*=}"
            shift
            ;;
        -d=* | --deployment=*)
            DEPLOYMENT="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
Generate Network Configuration

Arguments:
  -c=, --config=        specify the config.ini configuration file (Default: /boot/config/config.ini)
  -d=, --deployment=    specify the deployment.json configuration file (Default: /boot/config/deployment.json)
  -h, --help            show this help message and exit
  -o=, --output=        specify the systemd-networkd output directory (Default: /run/systemd/network)
'
            exit 1
            ;;
        -o=* | --output=*)
            OUTPUT="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

# Set arguments if undefined
CONFIG="${CONFIG:=/boot/config/config.ini}"
DEPLOYMENT="${DEPLOYMENT:=/boot/config/deployment.json}"
OUTPUT="${OUTPUT:=/run/systemd/network}"

function validate_arguments() {
    if [ "${CONFIG}" == "" -o "${DEPLOYMENT}" == "" -o "${OUTPUT}" == "" ]; then
        $0 --help
    fi
}

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_prefix") ipv6_prefix="${value}" ;;
            "ipv6_subnet") ipv6_subnet="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
            "ipv6_address") ipv6_address="${value}" ;;
            "hostname") hostname="${value}" ;;
        esac
    done <"${CONFIG}"
}

function generate_name_server_list() {
    if [ "${NAME_SERVERS}" != "null" ]; then
        for name_server in ${NAME_SERVERS}; do
            echo DNS="${name_server}"
        done
    fi
}

# Convert MAC address to SLAAC compatible (EUI64) IPv6 address
function generate_ipv6_address() {
    if [ -z "${ipv6_address}" ]; then
        NAME_SERVERS="$(/opt/ic/bin/fetch-property.sh --key=.dns.name_servers --metric=hostos_dns_name_servers --config=${DEPLOYMENT})"
        MAC_6=$(/opt/ic/bin/generate-deterministic-mac.sh --version=6 --index=0)
        MAC_4=$(/opt/ic/bin/generate-deterministic-mac.sh --version=4 --index=0)
        IPV6_ADDRESS=$(/opt/ic/bin/generate-deterministic-ipv6.sh --index=0)
    else
        IPV6_ADDRESS="${ipv6_address}"
    fi
}

# Detect physical network interfaces
function detect_network_interfaces() {
    INTERFACES=($(find /sys/class/net -type l -not -lname '*virtual*' -exec basename '{}' ';' | sort))
    INTERFACES_10GBE=()
    INTERFACES_1GBE=()

    # Detect interface speed
    for interface in ${INTERFACES[@]}; do
        if [ "$(ethtool ${interface} | grep '10000baseT/Full')" ]; then
            INTERFACES_10GBE+=("${interface}")
        else
            INTERFACES_1GBE+=("${interface}")
        fi
    done
}

# Generate network configuration files
function generate_network_config() {
    if [ -d /run/systemd ]; then
        mkdir -p /run/systemd/network
    fi

    # 10 Gigabit Ethernet Network Interfaces
    for interface in ${INTERFACES_10GBE[0]}; do
        (
            cat <<EOF
[Match]
Name=${interface}

[Link]
RequiredForOnline=no
MTUBytes=1500

[Network]
Description=10 Gigabit Ethernet Network Interface
LLDP=true
EmitLLDP=true
Bond=bond4
EOF
        ) >"${OUTPUT}/10-${interface}.network"
    done

    # 10-bond4.netdev
    (
        if [ "${MAC_4}" != "" ]; then
            local MAC="MACAddress=${MAC_4}"
        fi
        cat <<EOF
[NetDev]
Name=bond4
Kind=bond
$(echo ${MAC})

[Bond]
Mode=active-backup
MIIMonitorSec=5
UpDelaySec=10
DownDelaySec=10
EOF
    ) >"${OUTPUT}/10-bond4.netdev"

    # 10-bond4.network
    (
        cat <<EOF
[Match]
Name=bond4

[Network]
Bridge=br4
EOF
    ) >"${OUTPUT}/10-bond4.network"

    # 10-br4.netdev
    (
        cat <<EOF
[NetDev]
Name=br4
Kind=bridge

[Bridge]
ForwardDelaySec=0
STP=false
EOF
    ) >"${OUTPUT}/10-br4.netdev"

    # 10-br4.network
    (
        cat <<EOF
[Match]
Name=br4

[Network]
DHCP=yes
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF
    ) >"${OUTPUT}/10-br4.network"

    # 10 Gigabit Ethernet Network Interfaces
    for interface in ${INTERFACES_10GBE[1]}; do
        (
            cat <<EOF
[Match]
Name=${interface}

[Link]
RequiredForOnline=no
MTUBytes=1500

[Network]
Description=10 Gigabit Ethernet Network Interface
LLDP=true
EmitLLDP=true
Bond=bond6
EOF
        ) >"${OUTPUT}/20-${interface}.network"
    done

    # 20-bond6.netdev
    (
        if [ "${MAC_4}" != "" ]; then
            local MAC="MACAddress=${MAC_6}"
        fi
        cat <<EOF
[NetDev]
Name=bond6
Kind=bond
$(echo ${MAC})

[Bond]
Mode=active-backup
MIIMonitorSec=5
UpDelaySec=10
DownDelaySec=10
EOF
    ) >"${OUTPUT}/20-bond6.netdev"

    # 20-bond6.network
    (
        cat <<EOF
[Match]
Name=bond6

[Network]
Bridge=br6
EOF
    ) >"${OUTPUT}/20-bond6.network"

    # 20-br6.netdev
    (
        cat <<EOF
[NetDev]
Name=br6
Kind=bridge

[Bridge]
ForwardDelaySec=0
STP=false
EOF
    ) >"${OUTPUT}/20-br6.netdev"

    # 20-br6.network
    (
        cat <<EOF
[Match]
Name=br6

[Network]
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=yes
Address=$(echo ${IPV6_ADDRESS})
Gateway=$(echo ${ipv6_gateway})
EOF
        generate_name_server_list
    ) >"${OUTPUT}/20-br6.network"

    # 1 Gigabit Ethernet Network Interfaces
    for interface in ${INTERFACES_1GBE[@]}; do
        (
            if [ "${#INTERFACES_1GBE[@]}" -eq "1" ]; then
                local BOND="Bond=bond6"
            fi
            cat <<EOF
[Match]
Name=${interface}

[Link]
RequiredForOnline=no
MTUBytes=1500

[Network]
Description=1 Gigabit Ethernet Network Interface
DHCP=no
IPv6AcceptRA=no
$(echo ${BOND})
EOF
        ) >"${OUTPUT}/30-${interface}.network"
    done
}

function main() {
    # Establish run order
    validate_arguments
    read_variables
    detect_network_interfaces
    generate_ipv6_address
    generate_network_config
}

main
