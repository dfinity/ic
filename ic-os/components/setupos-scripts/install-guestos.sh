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
    # Extract the disk image to RAM.  Cannot be run concurrently with install-hostos.sh.
    echo "* Temporarily extracting the GuestOS image to RAM; please stand by for a few seconds"
    tar xaf /data/guest-os.img.tar.zst -C "${TMPDIR}" disk.img
    log_and_halt_installation_on_error "${?}" "Unable to extract GuestOS disk-image."
    # Write the extracted image to the disk.
    # Progress is handled by status=progress.
    # dd will detect nulls in chunks of 4M and sparsify the writes.
    # Makes a huge difference when running the setup under QEMU with no KVM.
    # In *non-KVM-accelerated* VM, this goes 500 MB/s, three times as fast as before.
    echo "* Writing the GuestOS image to ${LV}"
    dd if="${TMPDIR}/disk.img" of=${LV} bs=4M conv=sparse status=progress
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
