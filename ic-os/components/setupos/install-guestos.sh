#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

LV="/dev/mapper/hostlvm-guestos"

function install_guestos() {
    echo "* Installing GuestOS disk-image..."

    vgchange -ay hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to activate HostOS volume group."

    TMPDIR=$(mktemp -d)
    echo "* Extracting GuestOS image..."
    tar xaf /data/guest-os.img.tar.zst -C "${TMPDIR}" disk.img
    log_and_halt_installation_on_error "${?}" "Unable to extract GuestOS disk-image."

    echo "* Writing the GuestOS image to ${LV}..."
    dd if="${TMPDIR}/disk.img" of=${LV} bs=10M conv=sparse status=progress
    log_and_halt_installation_on_error "${?}" "Unable to install GuestOS disk-image."

    rm -rf "${TMPDIR}"

    sync
    log_and_halt_installation_on_error "${?}" "Unable to synchronize cached writes to persistent storage."

    vgchange -an hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to deactivate HostOS volume group."
}

# Establish run order
main() {
    log_start "$(basename $0)"
    install_guestos
    log_end "$(basename $0)"
}

main
