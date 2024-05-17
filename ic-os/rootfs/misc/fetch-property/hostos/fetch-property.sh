#!/bin/bash

set -e

# Fetch configuration property

# Source the functions required for writing metrics
source /opt/ic/bin/metrics.sh

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

write_log() {
    local message=$1

    if [ -t 1 ]; then
        echo "${SCRIPT} ${message}" >/dev/stdout
    fi

    logger -t ${SCRIPT} "${message}"
}

function fetch_property() {
    PROPERTY=$(jq -r "$(echo ${KEY})" ${CONFIG})

    if [ -z "${PROPERTY}" -o "${PROPERTY}" == "null" ]; then
        write_log "ERROR: Unable to fetch property: ${KEY}"
        write_metric "$(echo ${METRIC})" \
            "1" \
            "Property: $(echo ${KEY})" \
            "gauge"
        exit 1
    else
        write_log "Using property: ${PROPERTY}"
        write_metric "$(echo ${METRIC})" \
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
