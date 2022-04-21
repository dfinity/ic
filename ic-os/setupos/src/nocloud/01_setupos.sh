#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function install_ubuntu_packages() {
    echo "* Installing Ubuntu packages..."

    apt install -y --no-install-recommends \
        /media/cdrom/nocloud/libonig5.deb \
        /media/cdrom/nocloud/libjq1.deb \
        /media/cdrom/nocloud/jq.deb >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to install 'jq'."

    apt install -y --no-install-recommends \
        /media/cdrom/nocloud/efibootmgr.deb >/dev/null 2>&1
    log_and_reboot_on_error "${?}" "Unable to install 'efibootmgr'."
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    install_ubuntu_packages
    log_end
}

main
