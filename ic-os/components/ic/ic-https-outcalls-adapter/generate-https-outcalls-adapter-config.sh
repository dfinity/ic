#!/bin/bash

function usage() {
    cat <<EOF
Usage:
  generate-https-outcalls-adapter-config -o ic-https-outcalls-adapter.json5

  Generate the canister http adapter config.

  -o outfile: output ic-btc-adapter.json5 file
EOF
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

while getopts "o:s:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        s)
            SOCKS_FILE="${OPTARG}"
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

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

echo '{
    "logger": {
        "format": "json",
        "level": "info"
    },
    "socks_proxy": '\"${SOCKS_PROXY}\"'
}' >$OUT_FILE

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
