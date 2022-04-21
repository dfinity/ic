#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

LV="/dev/mapper/hostlvm-guestos"

function install_guestos() {
    echo "* Installing GuestOS disk-image to ${LV} (can take up to 3 minutes)..."

    vgchange -ay hostlvm
    log_and_reboot_on_error "${?}" "Unable to activate HostOS volume group."

    tar xzOf /media/cdrom/nocloud/guest-os.img.tar.gz disk.img | dd of=${LV} bs=10M
    log_and_reboot_on_error "${?}" "Unable to install GuestOS disk-image."

    sync
    log_and_reboot_on_error "${?}" "Unable to synchronize cached writes to persistent storage."

    vgchange -an hostlvm
    log_and_reboot_on_error "${?}" "Unable to deactivate HostOS volume group."
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    install_guestos
    log_end
}

main
