#!/usr/bin/env bash

set -o nounset
set -o pipefail

source /opt/ic/bin/config.sh
source /opt/ic/bin/functions.sh

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"
CONFIG_DIR="/config"

function mount_config_partition() {
    echo "* Mounting hostOS config partition..."

    vgchange -ay hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to activate hostOS config partition."

    mount /dev/mapper/hostlvm-config /media
    log_and_halt_installation_on_error "${?}" "Unable to mount hostOS config partition."
}

function copy_config_files() {
    echo "* Copying 'config.ini' to hostOS config partition..."
    if [ -f "${CONFIG_DIR}/config.ini" ]; then
        cp ${CONFIG_DIR}/config.ini /media/
        log_and_halt_installation_on_error "${?}" "Unable to copy 'config.ini' to hostOS config partition."
    else
        log_and_halt_installation_on_error "1" "Configuration file 'config.ini' does not exist."
    fi

    echo "* Copying SSH authorized keys..."
    ssh_authorized_keys=$(get_config_value '.icos_settings.ssh_authorized_keys_path')
    if [ -n "${ssh_authorized_keys}" ] && [ "${ssh_authorized_keys}" != "null" ]; then
        if [ -d "${ssh_authorized_keys}" ]; then
            cp -a "${ssh_authorized_keys}" /media/
            log_and_halt_installation_on_error "${?}" "Unable to copy SSH authorized keys to hostOS config partition."
        else
            log_and_halt_installation_on_error "1" "Directory '${ssh_authorized_keys}' does not exist."
        fi
    else
        echo >&2 "Warning: SSH authorized keys path is not configured."
    fi

    echo "* Copying node operator private key..."
    node_operator_private_key_path=$(get_config_value '.icos_settings.node_operator_private_key_path')
    if [ "${node_operator_private_key_path}" != "null" ] && [ -f "${node_operator_private_key_path}" ]; then
        cp "${node_operator_private_key_path}" /media/
        log_and_halt_installation_on_error "${?}" "Unable to copy node operator private key to hostOS config partition."
    elif [ "${node_operator_private_key_path}" = "null" ]; then
        echo >&2 "Warning: Node operator private key path is not configured."
    else
        echo >&2 "Warning: node_operator_private_key.pem does not exist, requiring HSM."
    fi

    echo "* Copying deployment.json to config partition..."
    cp /data/deployment.json /media/
    log_and_halt_installation_on_error "${?}" "Unable to copy deployment.json to hostOS config partition."

    echo "* Copying NNS public key to hostOS config partition..."
    nns_public_key_path=$(get_config_value '.icos_settings.nns_public_key_path')
    cp "${nns_public_key_path}" /media/
    log_and_halt_installation_on_error "${?}" "Unable to copy NNS public key to hostOS config partition."

    echo "* Converting 'config.json' to hostOS config file 'config-hostos.json'..."
    /opt/ic/bin/config generate-hostos-config

    # TODO: NODE-1466: Configuration revamp (HostOS and GuestOS integration)
    # echo "* Copying 'config-hostos.json' to hostOS config partition..."
    # if [ -f "/var/ic/config/config-hostos.json" ]; then
    #     cp /var/ic/config/config-hostos.json /media/config.json
    #     log_and_halt_installation_on_error "${?}" "Unable to copy 'config-hostos.json' to hostOS config partition."
    # else
    #     log_and_halt_installation_on_error "1" "Configuration file 'config-hostos.json' does not exist."
    # fi
}

function insert_hsm_if_necessary() {
    if [ ! -f "${CONFIG_DIR}/node_operator_private_key.pem" ]; then
        retry=0
        while [ -z "$(lsusb | grep -E 'Nitro|Clay')" ]; do
            let retry=retry+1
            if [ ${retry} -ge 3600 ]; then
                log_and_halt_installation_on_error "1" "Nitrokey HSM USB device could not be detected, giving up."
                break
            else
                echo "* Please insert Nitrokey HSM USB device..."
                sleep 3
            fi
        done
    fi
}

function unmount_config_partition() {
    echo "* Unmounting hostOS config partition..."

    sync
    log_and_halt_installation_on_error "${?}" "Unable to synchronize cached writes to persistent storage."

    umount /media
    log_and_halt_installation_on_error "${?}" "Unable to unmount hostOS config partition."

    vgchange -an hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to deactivate hostOS config partition."
}

# Establish run order
main() {
    log_start "$(basename $0)"
    mount_config_partition
    copy_config_files
    insert_hsm_if_necessary
    unmount_config_partition
    log_end "$(basename $0)"
}

main
