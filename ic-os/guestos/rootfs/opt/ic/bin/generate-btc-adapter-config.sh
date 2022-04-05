#!/bin/bash

# Read bitcoind addr config variables. The file must be of the form "key=value" for each
# line with a specific set of keys permissible (see code below).
#
# Arguments:
# - $1: Name of the file to be read.
function read_bitcoind_addr_variables() {
    while IFS="=" read -r key value; do
        case "$key" in
            "bitcoind_addr") bitcoind_addr="${value}" ;;
        esac
    done <"$1"
}

function usage() {
    cat <<EOF
Usage:
  generate-btc-adapter-config [-b bitcoind_addr.conf] -o ic-btc-adapter.json5

  Generate the bitcoin adapter config.

  -b bitcoind_addr.conf: Optional, bitcoind address
  -o outfile: output ic-btc-adapter.json5 file
EOF
}

while getopts "n:o:b:" OPT; do
    case "${OPT}" in
        b)
            BITCOIND_ADDR_FILE="${OPTARG}"
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

if [ "${BITCOIND_ADDR_CONFIG_FILE}" != "" -a -e "${BITCOIND_ADDR_CONFIG_FILE}" ]; then
    read_bitcoind_addr_variables "${BITCOIND_ADDR_CONFIG_FILE}"
fi

default_dns_seeds='"testnet-seed.bitcoin.jonasschnelli.ch",
                    "seed.tbtc.petertodd.org",
                    "seed.testnet.bitcoin.sprovoost.nl",
                    "testnet-seed.bluematt.me"'
BITCOIND_ADDR="${bitcoind_addr:-$default_dns_seeds}"

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

echo '{
    "network": "testnet",
    "dns_seeds": ['"${BITCOIND_ADDR}"'],
    "ipv6_only": true
}' >$OUT_FILE

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
