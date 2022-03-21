#!/bin/bash

function usage() {
    cat <<EOF
Usage:
  generate-btc-adapter-config -o ic-btc-adapter.json5

  Generate the bitcoin adapter config.

  -o outfile: output ic-btc-adapter.json5 file
EOF
}

while getopts "n:o:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

echo '{
    "network": "testnet",
    "dns_seeds": [
        "testnet-seed.bitcoin.jonasschnelli.ch",
        "seed.tbtc.petertodd.org",
        "seed.testnet.bitcoin.sprovoost.nl",
        "testnet-seed.bluematt.me"
    ],
    "ipv6_only": true
}' >$OUT_FILE

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
