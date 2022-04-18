#!/bin/bash

set -e

# Fetch configuration property

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Set argument default
UNIQUE=0

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
  -u, --unique          optional: read per data center unique property (Default: 0)
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
        -u | --unique)
            UNIQUE=1
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

write_metric() {
    local name=$1
    local value=$2
    local help=$3
    local type=$4

    echo -e "# HELP ${name} ${help}\n# TYPE ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}

function fetch_hsm_fingerprint() {
    HSM_FINGERPRINT=$(/opt/ic/bin/hsm-utils.sh --fetch)

    if [ -z "${HSM_FINGERPRINT}" -o "${HSM_FINGERPRINT}" == "null" ]; then
        write_log "ERROR: HSM public key fingerprint is invalid."
        exit 1
    fi
}

function fetch_property() {
    if [ ${UNIQUE} -eq 1 ]; then
        fetch_hsm_fingerprint
        PROPERTY=$(jq -r ".network.dcs.\"${HSM_FINGERPRINT}\"$(echo ${KEY})" ${CONFIG})
    else
        PROPERTY=$(jq -r "$(echo ${KEY})" ${CONFIG})
    fi

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
