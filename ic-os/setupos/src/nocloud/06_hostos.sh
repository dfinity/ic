#!/usr/bin/env bash

set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function install_hostos() {
    echo "* Installing HostOS disk-image (can take up to 5 minutes)..."

    tar xzOf /media/cdrom/nocloud/host-os.img.tar.gz disk.img | dd of="/dev/nvme0n1" bs=10M
    log_and_reboot_on_error "${?}" "Unable to install HostOS disk-image on drive: /dev/nvme0n1"

    sync
    log_and_reboot_on_error "${?}" "Unable to synchronize cached writes to persistent storage."
}

function configure_efi() {
    echo "* Configuring EFI..."

    bootnum=$(efibootmgr --verbose | grep "IC-OS" | sed 's/Boot\([0-9A-F]*\).*/\1/')
    for b in ${bootnum}; do
        efibootmgr --delete-bootnum --bootnum ${b} >/dev/null 2>&1
        log_and_reboot_on_error "${?}" "Unable to delete existing 'IC-OS' boot entry."
    done

    efibootmgr --create --gpt --disk "/dev/nvme0n1p1" --loader "\EFI\BOOT\BOOTX64.EFI" --label "IC-OS" >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to create 'IC-OS' boot entry."

    efibootmgr --remove-dups >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to remove duplicate boot order entries."

    efibootmgr --verbose | grep "IC-OS" | efibootmgr -o $(sed 's/Boot\([0-9A-F]*\).*/\1/') >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to set EFI boot order."
}

function resize_partition() {
    echo "* Resizing partition..."

    sgdisk --move-second-header /dev/nvme0n1 >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to extend GPT data structures: /dev/nvme0n1"

    parted -s --align optimal /dev/nvme0n1 "resizepart 3 100%" >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to resize partition: /dev/nvme0n1p3"

    pvresize /dev/nvme0n1p3 >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to resize physical volume: /dev/nvme0n1p3"

    lvextend -l +100%FREE /dev/hostlvm/guestos >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to extend logical volume: /dev/hostlvm/guestos"
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    install_hostos
    configure_efi
    resize_partition
    log_end
}

main
