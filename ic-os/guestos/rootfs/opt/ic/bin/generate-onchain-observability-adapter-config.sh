#!/bin/bash

function usage() {
    cat <<EOF
Usage:
  generate-onchain-observability-adapter-config -o onchain-observability-adapter-specific-config.json

  Generates the params specific to the onchain observability adapter.

  -o outfile: output ic-onchain-observability-adapter.json file
EOF
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

if [ "${OUT_FILE}" == "" ]; then
    usage
    exit 1
fi

# Set "canister_client_url": "{URL}" to enable service
# TODO: Update report length to 1hr
echo '{
    "logger": {
        "format": "json",
        "level": "info"
    },
    "report_length_sec": 180,
    "sampling_interval_sec": 60
}' >$OUT_FILE

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
