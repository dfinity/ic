#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function apply_uefi_config() {
    echo "* Applying UEFI configuration..."

    true
    log_and_reboot_on_error "${?}" "Unable to apply UEFI configuration file."
}

function verify_uefi_config() {
    echo "* Verifying UEFI configuration..."

    true
    log_and_reboot_on_error "${?}" "Unable to apply UEFI configuration file."
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    apply_uefi_config
    verify_uefi_config
    log_end
}

main
