#!/bin/bash
# Generate the network configuration from the information set in the
# configuration store.

set -euox pipefail
source '/opt/ic/bin/helpers.shlib'

readonly NETWORK_CONFIG="${BOOT_DIR}/network.conf"

readonly SYSTEMD_NETWORK='/run/systemd/network'
readonly IPV6_NETWORK="${SYSTEMD_NETWORK}/10-enp1s0.network"
readonly IPV4_NETWORK="${SYSTEMD_NETWORK}/enp2s0.network"

HAS_IPV6=false
HAS_IPV4=false

# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see code
# below).
function read_variables() {
    if [[ ! -d "${BOOT_DIR}" ]]; then
        err "missing node configuration directory: ${BOOT_DIR}"
        exit 1
    fi
    if [[ ! -f "${NETWORK_CONFIG}" ]]; then
        err "missing network configuration: ${NETWORK_CONFIG}"
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
    done <"${NETWORK_CONFIG}"

    # Check the config
    if [[ -n "${ipv6_address:-}" ]]; then
        if [[ -n "${ipv6_gateway:-}" ]]; then
            HAS_IPV6=true
        else
            err "ipv6 override failed, ipv6_address='${ipv6_address}' but ipv6_gateway not found in ${NETWORK_CONFIG}"
        fi
    elif [[ -n "${ipv6_gateway:-}" ]]; then
        err "ipv6 override failed, ipv6_gateway was '${ipv6_gateway}' but ipv6_address not found in ${NETWORK_CONFIG}"
    fi

    if [[ -n "${ipv4_address:-}" ]]; then
        if [[ -n "${ipv4_gateway:-}" ]]; then
            HAS_IPV4=true
        else
            err "ipv4 override failed, ipv4_address was '${ipv4_address}' but ipv4_gateway not found in ${NETWORK_CONFIG}"
        fi
    elif [[ -n "${ipv4_gateway:-}" ]]; then
        err "ipv4 override failed, ipv4_gateway was '${ipv4_gateway}' but ipv4_address not found in ${NETWORK_CONFIG}"
    fi
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
    if [[ "${HAS_IPV6}" == "true" ]]; then
        echo Address=${ipv6_address}
        echo Gateway=${ipv6_gateway}
        echo IPv6AcceptRA=false
    else
        echo IPv6AcceptRA=true
    fi
}
function generate_ipv4_block() {
    # If we have an IPv4 address given, just configure it.
    if [[ "${HAS_IPV4}" == "true" ]]; then
        echo Address=${ipv4_address}
        echo Gateway=${ipv4_gateway}
    else
        echo DHCP=ipv4
        echo LinkLocalAddressing=no
    fi
}

# Generate network configuration files (according to variables set previously).
function generate_network_config() {
    mkdir -p "${SYSTEMD_NETWORK}"

    # Handle ipv6
    cat >"${IPV6_NETWORK}" <<EOF
[Match]
Name=enp1s0
Virtualization=!container

[Network]
$(generate_ipv6_block)
$(generate_name_server_list)
EOF

    # Handle ipv4
    cat >"${IPV4_NETWORK}" <<EOF
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
