#!/bin/bash
# Generate the network configuration from the information set in the
# configuration store.

set -euox pipefail

readonly BOOT_CONFIG='/boot/config'
readonly SYSTEMD_NETWORK='/run/systemd/network'
readonly NFTABLES='/run/ic-node/etc/nftables'

ipv4_http_ips=()
ipv6_http_ips=()
ipv6_debug_ips=()
ipv6_monitoring_ips=()

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
    if [ ! -f "${BOOT_CONFIG}/bn_vars.conf" ]; then
        err "missing bn_vars configuration: ${BOOT_CONFIG}/bn_vars.conf"
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
            "ipv6_replica_ips") ipv6_replica_ips="${value}" ;;
        esac
    done <"${BOOT_CONFIG}/network.conf"

    while IFS="=" read -r key value; do
        case "$key" in
            "ipv4_http_ips") ipv4_http_ips+=("${value}") ;;
            "ipv6_http_ips") ipv6_http_ips+=("${value}") ;;
            "ipv6_debug_ips") ipv6_debug_ips+=("${value}") ;;
            "ipv6_monitoring_ips") ipv6_monitoring_ips+=("${value}") ;;
        esac
    done <"${BOOT_CONFIG}/bn_vars.conf"
}

function generate_name_server_list() {
    for NAME_SERVER in $name_servers; do
        echo DNS="${NAME_SERVER}"
    done
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
$(
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
        generate_name_server_list
    )
EOF

    # Handle ipv4
    cat >"${SYSTEMD_NETWORK}/enp2s0.network" <<EOF
[Match]
Name=enp2s0

[Network]
$(
        # If we have an IPv4 address given, just configure it.
        if [ "${ipv4_address}" != "" ]; then
            echo Address=$ipv4_address
            echo Gateway=$ipv4_gateway
        else
            echo DHCP=ipv4
            echo LinkLocalAddressing=no
        fi
        generate_name_server_list
    )
EOF
}

# Add extra rules to nftables to limit access.
function generate_nftables_config() {
    mkdir -p "${NFTABLES}"

    cat >"${NFTABLES}/defs.ruleset" <<EOF
define ipv6_replica_ips = { $(
        IFS=,
        echo "${ipv6_replica_ips[*]}"
    ) }

define ipv4_http_ips = { $(
        IFS=,
        echo "${ipv4_http_ips[*]}"
    ) }

define ipv6_http_ips = { $(
        IFS=,
        echo "${ipv6_http_ips[*]}"
    ) }

define ipv6_debug_ips = { $(
        IFS=,
        echo "${ipv6_debug_ips[*]}"
    ) }

define ipv6_monitoring_ips = { $(
        IFS=,
        echo "${ipv6_monitoring_ips[*]}"
    ) }
EOF
}

function main() {
    read_variables
    generate_network_config
    generate_nftables_config
}

main "$@"
