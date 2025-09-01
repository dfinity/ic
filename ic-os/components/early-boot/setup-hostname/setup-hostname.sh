#!/bin/bash

set -e

# Set the transient or persistent hostname.

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/config.sh

SCRIPT="$(basename $0)[$$]"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -f=* | --file=*)
            FILE="${argument#*=}"
            shift
            ;;
        -h | --help)
            echo 'Usage:
Set Transient Or Persistent Hostname

Arguments:
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
FILE="${FILE:=/boot/config/node-id}"

function validate_arguments() {
    if [ "${FILE}" == "" -o "${TYPE}" == "" ]; then
        $0 --help
    fi
}

function read_config_variables() {
    mgmt_mac=$(get_config_value '.icos_settings.mgmt_mac')
    mgmt_mac=${mgmt_mac//:/} # Remove colons from mgmt_mac
    config_hostname=$(get_config_value '.guestos_settings.guestos_dev_settings.hostname')
}

function construct_hostname() {
    if [ -n "${config_hostname}" ]; then
        HOSTNAME=${config_hostname}
        write_log "Using manually configured hostname: ${HOSTNAME}"
    elif [[ -r ${FILE} && $(cat ${FILE}) != "" ]]; then
        HOSTNAME=$(echo ${TYPE}-${mgmt_mac}-$(cat ${FILE}))
        write_log "Using hostname: ${HOSTNAME}"
        write_metric "setup_hostname" \
            "1" \
            "Hostname" \
            "gauge"
    else
        HOSTNAME=$(echo ${TYPE}-${mgmt_mac})
        write_log "Using hostname: ${HOSTNAME}"
        write_metric "setup_hostname" \
            "0" \
            "Hostname" \
            "gauge"
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
    validate_arguments
    read_config_variables
    construct_hostname
    setup_hostname
}

main
