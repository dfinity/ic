#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function mount_src_config_partition() {
    echo "* Mounting source config partition..."

    mkdir --parents /media/config_src
    log_and_reboot_on_error "${?}" "Unable to create mount directory."

    # TODO: Use UUID or label instead of hard-coded path
    mount /dev/sda3 /media/config_src
    log_and_reboot_on_error "${?}" "Unable to mount config partition."
}

function mount_dst_config_partition() {
    echo "* Mounting destination config partition..."

    mkdir --parents /media/config_dst
    log_and_reboot_on_error "${?}" "Unable to create mount directory."

    vgchange -ay hostlvm
    log_and_reboot_on_error "${?}" "Unable to activate config partition."

    mount /dev/mapper/hostlvm-config /media/config_dst
    log_and_reboot_on_error "${?}" "Unable to mount config partition."
}

function copy_config_files() {
    echo "* Copying config.ini to config partition..."
    if [ -f "/media/config_src/config.ini" ]; then
        cp /media/config_src/config.ini /media/config_dst/config.ini
        log_and_reboot_on_error "${?}" "Unable to copy config.ini to config partition."
    else
        log_and_reboot_on_error "1" "Configuration file 'config.ini' does not exist."
    fi

    echo "* Copying SSH authorized keys..."
    if [ -d "/media/config_src/ssh_authorized_keys" ]; then
        cp -r /media/config_src/ssh_authorized_keys /media/config_dst/
        log_and_reboot_on_error "${?}" "Unable to copy SSH authorized keys to config partition."
    else
        log_and_reboot_on_error "1" "Directory 'ssh_authorized_keys' does not exist."
    fi

    echo "* Copying deployment.json to config partition..."
    cp /media/cdrom/nocloud/deployment.json /media/config_dst/deployment.json
    log_and_reboot_on_error "${?}" "Unable to copy deployment.json to config partition."

    echo "* Copying NNS public key to config partition..."
    cp /media/cdrom/nocloud/nns_public_key.pem /media/config_dst/nns_public_key.pem
    log_and_reboot_on_error "${?}" "Unable to copy NNS public key to config partition."
}

function insert_hsm() {
    retry=0
    while [ -z "$(lsusb | grep -E 'Nitro|Clay')" ]; do
        let retry=retry+1
        if [ ${retry} -ge 3600 ]; then
            log_and_reboot_on_error "1" "Nitrokey HSM USB device could not be detected, giving up."
            break
        else
            echo "* Please insert Nitrokey HSM USB device..."
            sleep 3
        fi
    done
}

function unmount_config_partition() {
    echo "* Unmounting config partition..."

    sync
    log_and_reboot_on_error "${?}" "Unable to synchronize cached writes to persistent storage."

    umount /media/config_src
    log_and_reboot_on_error "${?}" "Unable to unmount source config partition."

    umount /media/config_dst
    log_and_reboot_on_error "${?}" "Unable to unmount destination config partition."

    vgchange -an hostlvm
    log_and_reboot_on_error "${?}" "Unable to deactivate config partition."
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    mount_src_config_partition
    mount_dst_config_partition
    copy_config_files
    insert_hsm
    unmount_config_partition
    log_end
}

main
