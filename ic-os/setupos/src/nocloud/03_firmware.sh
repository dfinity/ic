#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function set_uefi() {
    echo "* Setting UEFI version..."

    true
    log_and_reboot_on_error "${?}" "Unable to set UEFI version."
}

function set_idrac() {
    echo "* Setting iDRAC version..."

    true
    log_and_reboot_on_error "${?}" "Unable to set iDRAC version."
}

function set_chipset() {
    echo "* Setting chipset version..."

    true
    log_and_reboot_on_error "${?}" "Unable to set chipset version."
}

function set_psu() {
    echo "* Setting PSU version..."

    true
    log_and_reboot_on_error "${?}" "Unable to set PSU version."
}

function set_nic() {
    echo "* Setting NIC version..."

    true
    log_and_reboot_on_error "${?}" "Unable to set NIC version."
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    set_uefi
    set_idrac
    set_chipset
    set_psu
    set_nic
    log_end
}

main
