#!/usr/bin/env bash

set -o nounset
set -o pipefail

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
    echo "* Copying 'config.json' to hostOS config partition..."
    if [ -f "/var/ic/config/config.json" ]; then
        cp /var/ic/config/config.json /media/
        log_and_halt_installation_on_error "${?}" "Unable to copy 'config.json' to hostOS config partition."
    else
        log_and_halt_installation_on_error "1" "Configuration file 'config.json' does not exist."
    fi

    echo "* Copying 'config.ini' to hostOS config partition..."
    if [ -f "${CONFIG_DIR}/config.ini" ]; then
        cp ${CONFIG_DIR}/config.ini /media/
        log_and_halt_installation_on_error "${?}" "Unable to copy 'config.ini' to hostOS config partition."
    else
        log_and_halt_installation_on_error "1" "Configuration file 'config.ini' does not exist."
    fi

    echo "* Copying SSH authorized keys..."
    if [ -d "${CONFIG_DIR}/ssh_authorized_keys" ]; then
        cp -r ${CONFIG_DIR}/ssh_authorized_keys /media/
        log_and_halt_installation_on_error "${?}" "Unable to copy SSH authorized keys to hostOS config partition."
    else
        log_and_halt_installation_on_error "1" "Directory 'ssh_authorized_keys' does not exist."
    fi

    echo "* Copying node operator private key..."
    if [ -f "${CONFIG_DIR}/node_operator_private_key.pem" ]; then
        cp ${CONFIG_DIR}/node_operator_private_key.pem /media/
        log_and_halt_installation_on_error "${?}" "Unable to copy node operator private key to hostOS config partition."
    else
        echo "node_operator_private_key.pem does not exist, requiring HSM."
    fi

    echo "* Copying deployment.json to config partition..."
    cp /data/deployment.json /media/
    log_and_halt_installation_on_error "${?}" "Unable to copy deployment.json to hostOS config partition."

    echo "* Copying NNS public key to hostOS config partition..."
    cp /data/nns_public_key.pem /media/
    log_and_halt_installation_on_error "${?}" "Unable to copy NNS public key to hostOS config partition."
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
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    mount_config_partition
    copy_config_files
    insert_hsm_if_necessary
    unmount_config_partition
    log_end "$(basename $0)"
}

main
