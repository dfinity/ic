#!/bin/bash

set -e

# Set the transient or persistent hostname.

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

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

function construct_hostname() {
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
    construct_hostname
    setup_hostname
}

main
