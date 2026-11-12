#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

LV="/dev/mapper/hostlvm-guestos"

function install_guestos() {
    echo "* Installing GuestOS disk-images..."

    vgchange -ay hostlvm
    log_and_halt_installation_on_error "${?}" "Unable to activate HostOS volume group."

    TMPDIR=$(mktemp -d)
    echo "* Extracting GuestOS image..."
    tar xaf /data/guest-os.img.tar.zst -C "${TMPDIR}" disk.img
    log_and_halt_installation_on_error "${?}" "Unable to extract GuestOS disk-image."

    local lvs=("${LV}"*)

    for lv in "${lvs[@]}"; do
        blkdiscard "${lv}" || echo "* WARNING: Unable to discard ${lv}, continuing..."
    done

    if [ "${#lvs[@]}" -eq 1 ]; then
        echo "* Writing the GuestOS image to ${lvs[0]}..."
        dd if="${TMPDIR}/disk.img" of="${lvs[0]}" bs=10M conv=sparse oflag=direct status=progress
        log_and_halt_installation_on_error "${?}" "Unable to install GuestOS disk-image to ${lvs[0]}."
    else
        echo "* Writing the GuestOS image to ${#lvs[@]} volumes..."
        printf '%s\n' "${lvs[@]}" | xargs -P 4 -I {} \
            sh -c 'dd if="$1" of=$2 bs=10M conv=sparse oflag=direct status=none && echo "* Finished writing to $2"' \
            _ "${TMPDIR}/disk.img" {}
        log_and_halt_installation_on_error "${?}" "Unable to install GuestOS disk-image."
    fi

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
