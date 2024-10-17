#!/bin/bash

set -ex

source /opt/ic/bin/config.sh

function read_config_variables() {
    hostname=$(get_config_value '.icos_settings.hostname')
    if [[ -z "${hostname}" || "${hostname}" == "null" ]]; then
        hostname="unnamed"
    fi
}

read_config_variables

echo "${hostname}" >/run/ic-node/etc/hostname
mount --bind /run/ic-node/etc/hostname /etc/hostname
restorecon -v /etc/hostname
hostname "${hostname}"
