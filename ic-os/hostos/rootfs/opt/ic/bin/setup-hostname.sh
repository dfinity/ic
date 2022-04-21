#!/bin/bash

set -e

# Set the transient or persistent hostname.

SCRIPT="$(basename $0)[$$]"
METRICS_DIR="/run/node_exporter/collector_textfile"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -c=* | --config=*)
            CONFIG="${argument#*=}"
            shift
            ;;
        -f=* | --file=*)
            FILE="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
Set Transient Or Persistent Hostname

Arguments:
  -c=, --config=        optional: specify the config.json configuration file (Default: /boot/config/config.json)
  -f=, --file=          optional: specify the file containing the node-id (Default: /boot/config/node-id)
  -h, --help            show this help message and exit
  -t=, --type=          mandatory: specify the node type (Examples: host, guest, boundary...)
'
            exit 1
            ;;
        -t=* | --type=*)
            TYPE="${argument#*=}"
            shift
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

# Set arguments if undefined
CONFIG="${CONFIG:=/boot/config/config.json}"
FILE="${FILE:=/boot/config/node-id}"

function validate_arguments() {
    if [ "${CONFIG}" == "" -o "${FILE}" == "" -o "${TYPE}" == "" ]; then
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

function construct_hostname() {
    # TODO: This field is not mandatory, so we need to be able to optionally grab it
    overrides=$(jq -r ".overrides" ${CONFIG})
    if [ "${overrides}" != "null" ]; then
        HOSTNAME=$(/opt/ic/bin/fetch-property.sh --key=.overrides.hostname --metric=overrides_hostname --config=${CONFIG})
    else
        local mac=$(/opt/ic/bin/fetch-mgmt-mac.sh | sed 's/://g')

        if [[ -r ${FILE} && $(cat ${FILE}) != "" ]]; then
            HOSTNAME=$(echo ${TYPE}-${mac}-$(cat ${FILE}))
            write_log "Using hostname: ${HOSTNAME}"
            write_metric "hostos_setup_hostname" \
                "1" \
                "HostOS setup hostname" \
                "gauge"
        else
            HOSTNAME=$(echo ${TYPE}-${mac})
            write_log "Using hostname: ${HOSTNAME}"
            write_metric "hostos_setup_hostname" \
                "0" \
                "HostOS setup hostname" \
                "gauge"
        fi
    fi
}

function setup_hostname() {
    if [ "$(mount | grep '/etc/hostname')" ]; then
        umount /etc/hostname
    fi

    if [ -d /run/ic-node/etc ]; then
        echo "${HOSTNAME}" >/run/ic-node/etc/hostname
        mount --bind /run/ic-node/etc/hostname /etc/hostname
        restorecon -v /etc/hostname
        hostname "${HOSTNAME}"
    fi
}

function main() {
    # Establish run order
    validate_arguments
    construct_hostname
    setup_hostname
}

main
