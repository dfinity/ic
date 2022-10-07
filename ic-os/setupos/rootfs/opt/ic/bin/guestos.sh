#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

LV="/dev/mapper/hostlvm-guestos"

function install_guestos() {
    echo "* Installing GuestOS disk-image..."

    vgchange -ay hostlvm
    log_and_reboot_on_error "${?}" "Unable to activate HostOS volume group."

    size=$(tar --list -v -f /data/guest-os.img.tar.gz disk.img | cut -d ' ' -f 3)
    size="${size:=0}"

    tar xzOf /data/guest-os.img.tar.gz disk.img | pv -f -s "$size" | dd of=${LV} bs=10M
    log_and_reboot_on_error "${?}" "Unable to install GuestOS disk-image."

    sync
    log_and_reboot_on_error "${?}" "Unable to synchronize cached writes to persistent storage."

    vgchange -an hostlvm
    log_and_reboot_on_error "${?}" "Unable to deactivate HostOS volume group."
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    install_guestos
    log_end "$(basename $0)"
}

main
