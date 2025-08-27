#!/bin/bash

source /opt/ic/bin/config.sh

function usage() {
    cat <<EOF
Usage:
  generate-https-outcalls-adapter-config -o ic-https-outcalls-adapter.json5

  Generate the canister http adapter config.

  -o outfile: output ic-btc-adapter.json5 file
EOF
}

function read_config_variables() {
    config_socks_proxy=$(get_config_value '.guestos_settings.guestos_dev_settings.socks_proxy')
}

while getopts "o:" OPT; do
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

read_config_variables

# Production socks5 proxy url needs to include schema, host and port to be accepted by the adapters.
# Testnets deploy with a development socks_proxy config value to overwrite the production socks proxy with the testnet proxy.
SOCKS_PROXY="socks5h://socks5.ic0.app:1080"
if [ "${config_socks_proxy}" != "" ] && [ "${config_socks_proxy}" != "null" ]; then
    SOCKS_PROXY="${config_socks_proxy}"
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
