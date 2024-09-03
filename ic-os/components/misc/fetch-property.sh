#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

# Fetch configuration property

source /opt/ic/bin/logging.sh

SCRIPT="$(basename $0)[$$]"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -c=* | --config=*)
            CONFIG="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
Fetch Configuration Property

Arguments:
  -c=, --config=        mandatory: specify the configuration file to read from
  -h, --help            show this help message and exit
  -k=, --key=           mandatory: specify the property key
  -m=, --metric=        mandatory: specify the metric name
'
            exit 1
            ;;
        -k=* | --key=*)
            KEY="${argument#*=}"
            shift
            ;;
        -m=* | --metric=*)
            METRIC="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

function validate_arguments() {
    if [ "${CONFIG}" == "" -o "${KEY}" == "" -o "${METRIC}" == "" ]; then
        $0 --help
    fi
}

try_write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    # metrics.sh is required for writing metrics
    # metrics.sh only exists on HostOS and GuestOS, not SetupOS
    if [ -f "/opt/ic/bin/metrics.sh" ]; then
        source "/opt/ic/bin/metrics.sh"
        write_metric "${name}" "${value}" "${help}" "${type}"
    fi
}

function fetch_property() {
    PROPERTY=$(jq -r "$(echo ${KEY})" ${CONFIG})

    if [ -z "${PROPERTY}" -o "${PROPERTY}" == "null" ]; then
        write_log "ERROR: Unable to fetch property: ${KEY}"
        try_write_metric "$(echo ${METRIC})" \
            "1" \
            "Property: $(echo ${KEY})" \
            "gauge"
        exit 1
    else
        write_log "Using property: ${PROPERTY}"
        try_write_metric "$(echo ${METRIC})" \
            "0" \
            "Property: $(echo ${KEY})" \
            "gauge"
        echo "${PROPERTY}"
    fi
}

function main() {
    # Establish run order
    validate_arguments
    fetch_property
}

main
