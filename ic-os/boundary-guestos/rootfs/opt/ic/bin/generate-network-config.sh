#!/bin/bash
# Generate the network configuration from the information set in the
# configuration store.

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly SYSTEMD_NETWORK='/run/systemd/network'

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see code
# below).
function read_variables() {
    if [[ ! -d "${BOOT_CONFIG}" ]]; then
        err "missing node configuration directory: ${BOOT_CONFIG}"
        exit 1
    fi
    if [[ ! -f "${BOOT_CONFIG}/network.conf" ]]; then
        err "missing network configuration: ${BOOT_CONFIG}/network.conf"
        exit 1
    fi

    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_address") ipv6_address="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
            "ipv4_address") ipv4_address="${value}" ;;
            "ipv4_gateway") ipv4_gateway="${value}" ;;
            "name_servers") name_servers="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/network.conf"
}

function generate_name_server_list() {
    for NAME_SERVER in $name_servers; do
        echo DNS="${NAME_SERVER}"
    done
}

function generate_ipv6_block() {
    # If we have an IPv6 address given, just configure it. Also, explicitly
    # turn off router advertisements, otherwise we may end up with two
    # (distinct) addresses on the same interface.
    if [ "${ipv6_address}" != "" ]; then
        echo Address=$ipv6_address
        echo Gateway=$ipv6_gateway
        echo IPv6AcceptRA=false
    else
        echo IPv6AcceptRA=true
    fi
}
function generate_ipv4_block() {
    # If we have an IPv4 address given, just configure it.
    if [ "${ipv4_address}" != "" ]; then
        echo Address=$ipv4_address
        echo Gateway=$ipv4_gateway
    else
        echo DHCP=ipv4
        echo LinkLocalAddressing=no
    fi
}

# Generate network configuration files (according to variables set previously).
function generate_network_config() {
    mkdir -p "${SYSTEMD_NETWORK}"

    # Handle ipv6
    cat >"${SYSTEMD_NETWORK}/10-enp1s0.network" <<EOF
[Match]
Name=enp1s0
Virtualization=!container

[Network]
$(generate_ipv6_block)
$(generate_name_server_list)
EOF

    # Handle ipv4
    cat >"${SYSTEMD_NETWORK}/enp2s0.network" <<EOF
[Match]
Name=enp2s0

[Network]
$(generate_ipv4_block)
$(generate_name_server_list)
EOF
}

function main() {
    read_variables
    generate_network_config
}

main "$@"
