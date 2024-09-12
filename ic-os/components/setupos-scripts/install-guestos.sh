#!/usr/bin/env bash

set -o nounset
set -o pipefail

source /opt/ic/bin/functions.sh

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

LV="/dev/mapper/hostlvm-guestos"

function install_guestos() {
    echo "* Installing GuestOS disk-image..."

    vgchange -ay hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to activate HostOS volume group."

    TMPDIR=$(mktemp -d)
    tar xafS /data/guest-os.img.tar.zst -C "${TMPDIR}" disk.img

    size=$(wc -c <"${TMPDIR}/disk.img")
    size="${size:=0}"

    pv -f -s "$size" "${TMPDIR}/disk.img" | dd of=${LV} bs=10M conv=sparse
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
