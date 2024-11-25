#!/bin/bash

# Substitute correct configuration parameters into nftables.conf.

function usage() {
    cat <<EOF
Usage:
  setup-nftables -n config.ini -i nftables.template -o nftables.conf

  Generate nftables config from template file.

  -n config.ini: network configuration description file
  -i infile: input ic.json5.template file
  -o outfile: output ic.json5 file
EOF
}

# XXX: the following function is duplicate with generate-network-config.sh
# -- consolidate
#
# Read the network config variables from file. The file must be of the form
# "key=value" for each line with a specific set of keys permissible (see
# code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_network_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "ipv6_prefix") ipv6_prefix="${value}" ;;
        esac
    done <"$1"
}

while getopts "n:i:o:" OPT; do
    case "${OPT}" in
        n)
            NETWORK_CONFIG_FILE="${OPTARG}"
            ;;
        i)
            IN_FILE="${OPTARG}"
            ;;
        o)
            OUT_FILE="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [ "${IN_FILE}" == "" -o "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

# TODO: This should be pulled from the system, in case of configuration via RA.
if [ "${NETWORK_CONFIG_FILE}" != "" -a -e "${NETWORK_CONFIG_FILE}" ]; then
    read_network_variables "${NETWORK_CONFIG_FILE}"
fi

IPV6_PREFIX="${ipv6_prefix:+${ipv6_prefix}::/64}" # Add suffix to prefix if found
IPV6_PREFIX="${IPV6_PREFIX:-::1/128}"             # Default to loopback for easy templating

mkdir -p /run/ic-node/nftables-ruleset/
sed -e "s@{{ ipv6_prefix }}@${IPV6_PREFIX}@" \
    "${IN_FILE}" >"${OUT_FILE}"
