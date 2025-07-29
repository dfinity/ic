#!/bin/bash

# Read bitcoind addr config variables. The file must be of the form "key=value" for each
# line with a specific set of keys permissible (see code below).
#
# Arguments:
# - $1: Name of the file to be read.

source /opt/ic/bin/config.sh

function read_config_variables() {
    config_bitcoind_addr=$(get_config_value '.guestos_settings.guestos_dev_settings.bitcoind_addr')
    config_socks_proxy=$(get_config_value '.guestos_settings.guestos_dev_settings.socks_proxy')
}

function usage() {
    cat <<EOF
Usage:
  generate-btc-adapter-config -o ic-btc-adapter.json5

  Generate the bitcoin adapter config.

  -m If set, we will use bitcoin mainnet dns seeds
  -o outfile: output ic-btc-adapter.json5 file
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

# Production socks5 proxy url needs to include schema, host and port to be accepted by the adapters.
# Testnets deploy with a development socks_proxy config value to overwrite the production socks proxy with the testnet proxy.
SOCKS_PROXY="socks5://socks5.ic0.app:1080"
if [ "${config_socks_proxy}" != "" ] && [ "${config_socks_proxy}" != "null" ]; then
    SOCKS_PROXY="${config_socks_proxy}"
fi

BITCOIN_NETWORK='"testnet4"'
DNS_SEEDS='"seed.testnet4.bitcoin.sprovoost.nl",
            "seed.testnet4.wiz.biz"'

if [ "$MAINNET" = true ]; then
    BITCOIN_NETWORK='"bitcoin"'
    DNS_SEEDS='"seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.org",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz"'
fi

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

# config_bitcoind_addr indicates that we are in system test environment. No socks proxy needed.
if [ "${config_bitcoind_addr}" != "" ] && [ "${config_bitcoind_addr}" != "null" ]; then
    echo '{
        "network": "regtest",
        "dns_seeds": [],
        "nodes": ['"${config_bitcoind_addr:+\"${config_bitcoind_addr//,/\",\"}\"}"'],
        "logger": {
            "format": "json",
            "level": "info"
        }
    }' >$OUT_FILE
else
    echo '{
        "network": '"${BITCOIN_NETWORK}"',
        "dns_seeds": ['"${DNS_SEEDS}"'],
        "logger": {
            "format": "json",
            "level": "info"
        }
    }' >$OUT_FILE
fi

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
