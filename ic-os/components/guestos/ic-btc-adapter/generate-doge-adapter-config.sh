#!/bin/bash

# Read dogecoind addr config variables. The file must be of the form "key=value" for each
# line with a specific set of keys permissible (see code below).
#
# Arguments:
# - $1: Name of the file to be read.

source /opt/ic/bin/config.sh

function read_config_variables() {
    config_dogecoind_addr=$(get_config_value '.guestos_settings.guestos_dev_settings.dogecoind_addr')
}

function usage() {
    cat <<EOF
Usage:
  generate-doge-adapter-config -o ic-doge-adapter.json5

  Generate the dogecoin adapter config.

  -m If set, we will use dogecoin mainnet dns seeds
  -o outfile: output ic-doge-adapter.json5 file
EOF
}

MAINNET=false
while getopts "mo:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        m)
            MAINNET=true
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

read_config_variables

DOGECOIN_NETWORK='"dogecoin:testnet"'
CACHE_NAME='dogecoin_testnet_cache'
DNS_SEEDS='"jrn.me.uk",
            "testseed.jrn.me.uk"'

if [ "$MAINNET" = true ]; then
    DOGECOIN_NETWORK='"dogecoin"'
    CACHE_NAME='dogecoin_mainnet_cache'
    DNS_SEEDS='"seed.multidoge.org",
            "seed2.multidoge.org"'
fi

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

# config_dogecoind_addr indicates that we are in system test environment.
if [ "${config_dogecoind_addr}" != "" ] && [ "${config_dogecoind_addr}" != "null" ]; then
    echo '{
        "network": "dogecoin:regtest",
        "dns_seeds": [],
        "nodes": ['"${config_dogecoind_addr:+\"${config_dogecoind_addr//,/\",\"}\"}"'],
        "logger": {
            "format": "json",
            "level": "info"
        }
    }' >$OUT_FILE
else
    CACHE_DIR="\"/var/lib/ic/data/ic_adapter/${CACHE_NAME}\""
    echo '{
        "network": '"${DOGECOIN_NETWORK}"',
        "dns_seeds": ['"${DNS_SEEDS}"'],
        "cache_dir": '"${CACHE_DIR}"',
        "logger": {
            "format": "json",
            "level": "info"
        }
    }' >$OUT_FILE
fi

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
