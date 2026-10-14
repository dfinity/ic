#!/usr/bin/env bash

# Mount config and data partitions from the USB SetupOS is booting from

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

main() {
    log_start "$(basename $0)"

    root_part=$(readlink -f "$(findmnt --noheadings --nofsroot --output SOURCE --target /)")

    if [[ "${root_part}" != *6 ]]; then
        log_and_halt_installation_on_error 1 "SetupOS is running from '${root_part}', not partition 6. Unable to detect boot drive."
    fi
    media="${root_part%6}"

    echo "* Mounting ${media}3 at /config and ${media}4 at /data"

    mount -t vfat -o nosuid,nodev,noexec "${media}3" /config
    log_and_halt_installation_on_error "${?}" "Unable to mount ${media}3 at /config."

    mount -t ext4 -o sync,nosuid,nodev,noexec "${media}4" /data
    log_and_halt_installation_on_error "${?}" "Unable to mount ${media}4 at /data."

    log_end "$(basename $0)"
}

main
