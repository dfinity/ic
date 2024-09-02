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

# Reads the socks proxy config file. The file must be of the form "key=value".
# The file should only contain the key `socks_proxy`. All other keys are ignored.
#
# Arguments:
# - $1: Name of the file to be read.
function read_socks_proxy() {
    while IFS="=" read -r key value; do
        case "$key" in
            "socks_proxy") SOCKS_PROXY="${value}" ;;
        esac
    done <"$1"
}

function usage() {
    cat <<EOF
Usage:
  generate-btc-adapter-config [-b bitcoind_addr.conf] [-s socks_proxy.conf] -o ic-btc-adapter.json5

  Generate the bitcoin adapter config.

  -b bitcoind_addr.conf: Optional, bitcoind address
  -s socks_proxy.conf: Optional, socks proxy url
  -m If set, we will use bitcoin mainnet dns seeds 
  -o outfile: output ic-btc-adapter.json5 file
EOF
}

MAINNET=false
while getopts "b:mo:s:" OPT; do
    case "${OPT}" in
        b)
            BITCOIND_ADDR_FILE="${OPTARG}"
            ;;
        s)
            SOCKS_FILE="${OPTARG}"
            ;;
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

# Production socks5 proxy url needs to include schema, host and port to be accepted by the adapters.
# Testnets deploy with a 'socks_proxy.conf' file to overwrite the production socks proxy with the testnet proxy.
SOCKS_PROXY="socks5://socks5.ic0.app:1080"
if [ "${SOCKS_FILE}" != "" -a -e "${SOCKS_FILE}" ]; then
    read_socks_proxy "${SOCKS_FILE}"
fi

BITCOIN_NETWORK='"testnet"'
DNS_SEEDS='"testnet-seed.bitcoin.jonasschnelli.ch",
            "seed.tbtc.petertodd.org",
            "seed.testnet.bitcoin.sprovoost.nl",
            "testnet-seed.bluematt.me"'

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

# BITCOIND_ADDR indicates that we are in system test environment. No socks proxy needed.
# bitcoin_addr.conf should be formatted like this: key 'bitcoind_addr', comma separated values, NO "" around addresses, NO trailing ',' AND spaces
# Example: bitcoind_addr=seed.bitcoin.sipa.be,regtest.random.me,regtest.random.org
#
# Bash explanation:
# ${bitcoind_addr:+\"${bitcoind_addr//,/\",\"}\"}
# ${parameter:+word}: If parameter is null or unset, nothing is substituted, otherwise the expansion of word is substituted.
# word: \"${bitcoind_addr//,/\",\"}\" Adds surrounding "" and matches and replaces all ',' with '","'
if [ "${BITCOIND_ADDR_FILE}" != "" -a -e "${BITCOIND_ADDR_FILE}" ]; then
    read_bitcoind_addr_variables "${BITCOIND_ADDR_FILE}"
    echo '{
        "network": "regtest",
        "dns_seeds": [],
        "nodes": ['"${bitcoind_addr:+\"${bitcoind_addr//,/\",\"}\"}"'],
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
