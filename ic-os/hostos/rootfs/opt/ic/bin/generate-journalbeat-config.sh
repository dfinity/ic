#!/bin/bash

set -e

# Generate the Journalbeat configuration.

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -c=* | --config=*)
            CONFIG="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
Generate Journalbeat Configuration

Arguments:
  -c=, --config=        specify the deployment.json configuration file (Default: /boot/config/deployment.json)
  -h, --help            show this help message and exit
  -i=, --input=         specify the input template file (Default: /etc/journalbeat/journalbeat.yml.template)
  -o=, --output=        specify the output configuration file (Default: /run/ic-node/etc/journalbeat/journalbeat.yml)
'
            exit 1
            ;;
        -i=* | --input=*)
            INPUT="${argument#*=}"
            shift
            ;;
        -o=* | --output=*)
            OUTPUT="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

# Set arguments if undefined
CONFIG="${CONFIG:=/boot/config/deployment.json}"
INPUT="${INPUT:=/etc/journalbeat/journalbeat.yml.template}"
OUTPUT="${OUTPUT:=/run/ic-node/etc/journalbeat/journalbeat.yml}"

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

    echo -e "# HELP ${name} ${help}\n# INDEX ${type}\n${name} ${value}" >"${METRICS_DIR}/${name}.prom"
}

function generate_journalbeat_config() {
    JOURNALBEAT_HOSTS=$(/opt/ic/bin/fetch-property.sh --key=.logging.hosts --metric=hostos_logging_hosts --config=${CONFIG})

    if [ "${JOURNALBEAT_HOSTS}" != "" ]; then
        # Covert string into comma separated array
        if [ "$(echo ${JOURNALBEAT_HOSTS} | grep ':')" ]; then
            journalbeat_hosts_array=$(for host in ${JOURNALBEAT_HOSTS}; do echo -n "\"${host}\", "; done | sed -E "s@, \$@@g")
        else
            journalbeat_hosts_array=$(for host in ${JOURNALBEAT_HOSTS}; do echo -n "\"${host}:443\", "; done | sed -E "s@, \$@@g")
        fi
        sed -e "s@{{ journalbeat_hosts }}@${journalbeat_hosts_array}@" "${INPUT}" >"${OUTPUT}"
    fi
}

function main() {
    # Establish run order
    generate_journalbeat_config
}

main
