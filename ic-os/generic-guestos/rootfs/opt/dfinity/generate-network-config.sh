#!/bin/bash

# Generate the network configuration from the information set in the
# configuration store.
#
# Arguments:
# - $1: Name of the input file to be read
# - $2: Base path of output files
#
# Will do nothing if the input file given as first argument does not exist.

# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv4_address") ipv4_address="${value}" ;;
            "ipv6_address") ipv6_address="${value}" ;;
            "ipv4_gateway") ipv4_gateway="${value}" ;;
            "ipv6_gateway") ipv6_gateway="${value}" ;;
            "name_servers") name_servers="${value}" ;;
        esac
    done <"$1"
}

function generate_name_server_list() {
    for NAME_SERVER in $name_servers; do
        echo DNS="${NAME_SERVER}"
    done
}

# Generate network configuration files (according to variables set previously).
#
# Arguments:
# - $1: Name of output directory for generated network config files.
#       Should be /run/systemd/network/ for production.
function generate_config_files() {
    TARGET_DIR="$1"
    (
        cat <<EOF
[Match]
Name=enp1s0
Virtualization=!container

EOF

        if [ "${ipv6_address}" != "" ]; then
            # If we have an IPv6 address given, just configure
            # it. Also, explicitly turn off router advertisements,
            # otherwise we may end up with two (distinct)
            # addresses on the same interface.
            cat <<EOF
[Network]
Address=$ipv6_address
Gateway=$ipv6_gateway
IPv6AcceptRA=false
EOF

        else
            cat <<EOF

[Network]
IPv6AcceptRA=true
EOF
        fi
        generate_name_server_list
    ) >"${TARGET_DIR}/10-enp1s0.network"
    (
        cat <<EOF
[Match]
Name=enp2s0
Virtualization=!container

EOF

        if [ "${ipv4_address}" != "" ]; then
            cat <<EOF
[Network]
Address=$ipv4_address
Gateway=$ipv4_gateway
EOF
        else
            cat <<EOF
[Network]
DHCP=v4
EOF
        fi
    ) >"${TARGET_DIR}/20-enp2s0.network"
}

if [ -e "$1" ]; then
    read_variables "$1"
fi
mkdir -p "$2"
generate_config_files "$2"
