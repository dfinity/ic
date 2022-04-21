#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function mount_config_partition() {
    echo "* Mounting config partition..."

    mkdir --parents /media/config
    log_and_reboot_on_error "${?}" "Unable to create mount directory."

    vgchange -ay hostlvm
    log_and_reboot_on_error "${?}" "Unable to activate config partition."

    mount /dev/mapper/hostlvm-config /media/config
    log_and_reboot_on_error "${?}" "Unable to mount config partition."
}

function copy_config_files() {
    echo "* Copying config.json to config partition..."
    cp /media/cdrom/nocloud/config.json /media/config/config.json
    log_and_reboot_on_error "${?}" "Unable to copy config.json to config partition."

    echo "* Copying deployment.json to config partition..."
    cp /media/cdrom/nocloud/deployment.json /media/config/deployment.json
    log_and_reboot_on_error "${?}" "Unable to copy deployment.json to config partition."

    echo "* Copying NNS public key to config partition..."
    cp /media/cdrom/nocloud/nns_public_key.pem /media/config/nns_public_key.pem
    log_and_reboot_on_error "${?}" "Unable to copy NNS public key to config partition."

    if [ -d "/media/cdrom/nocloud/hostos_accounts_ssh_authorized_keys" ]; then
        echo "* Copying HostOS accounts SSH authorized keys..."
        cp -r /media/cdrom/nocloud/hostos_accounts_ssh_authorized_keys /media/config/
        log_and_reboot_on_error "${?}" "Unable to copy HostOS accounts SSH authorized keys to config partition."
    fi

    if [ -d "/media/cdrom/nocloud/guestos_accounts_ssh_authorized_keys" ]; then
        echo "* Copying GuestOS accounts SSH authorized keys..."
        cp -r /media/cdrom/nocloud/guestos_accounts_ssh_authorized_keys /media/config/
        log_and_reboot_on_error "${?}" "Unable to copy GuestOS accounts SSH authorized keys to config partition."
    fi
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

    umount /media/config
    log_and_reboot_on_error "${?}" "Unable to unmount config partition."

    vgchange -an hostlvm
    log_and_reboot_on_error "${?}" "Unable to deactivate config partition."
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    mount_config_partition
    copy_config_files
    insert_hsm
    unmount_config_partition
    log_end
}

main
