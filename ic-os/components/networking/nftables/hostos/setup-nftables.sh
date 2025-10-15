#!/bin/bash

# Substitute correct configuration parameters into nftables.conf.

source /opt/ic/bin/config.sh

function usage() {
    cat <<EOF
Usage:
  setup-nftables -i nftables.template -o nftables.conf

  Generate nftables config from template file.

  -i infile: input nftables.template file
  -o outfile: output nftables.conf file
EOF
}

function get_ipv6_prefix() {
    ipv6_prefix=$(get_config_value '.network_settings.ipv6_config.Deterministic.prefix')
    IPV6_PREFIX="${ipv6_prefix:+${ipv6_prefix}::/64}" # Add suffix to prefix if found
    IPV6_PREFIX="${IPV6_PREFIX:-::1/128}"             # Default to loopback for easy templating
}

while getopts "i:o:" OPT; do
    case "${OPT}" in
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

get_ipv6_prefix

mkdir -p /run/ic-node/nftables-ruleset/
sed -e "s@{{ ipv6_prefix }}@${IPV6_PREFIX}@" \
    "${IN_FILE}" >"${OUT_FILE}"
