#!/bin/bash

function usage() {
    cat <<EOF
Usage:
  generate-onchain-observability-adapter-config -o onchain-observability-adapter-specific-config.json

  Generates the params specific to the onchain observability adapter.

  -o outfile: output ic-onchain-observability-adapter.json file

  -t test overrides: json of params that will override any existing values for system testings
EOF
}

# Adds override fields to config and outputs the new config.
#
# Arguments:
# - $1: original config
# - $2: override config
function apply_overrides() {
    local config=$1
    local overrides=$2

    for key in $(cat "$overrides" | jq 'keys[]'); do
        local value=$(cat "$overrides" | jq -r .$key)
        config=$(echo $config | jq ".$key |= $value")
    done
    echo $config
}

while getopts "o:t:" OPT; do
    case "${OPT}" in
        o)
            OUT_FILE="${OPTARG}"
            ;;
        t)
            OVERRIDES="${OPTARG}"
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

CONFIG='{
    "logger": {
        "format": "json",
        "level": "info"
    },
    "report_length_sec": 3600,
    "sampling_interval_sec": 60,
    "canister_id": "3kvk3-xyaaa-aaaae-qaesq-cai"
}'

if [ "${OVERRIDES}" != "" -a -e "${OVERRIDES}" ]; then
    echo $(apply_overrides "${CONFIG}" "${OVERRIDES}") >$OUT_FILE
else
    echo "${CONFIG}" >$OUT_FILE
fi

# umask for service is set to be restricted, but this file needs to be
# world-readable
chmod 644 "${OUT_FILE}"
