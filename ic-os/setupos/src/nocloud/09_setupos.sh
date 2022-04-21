#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function reboot_setupos() {
    echo "* Rebooting SetupOS..."
    echo " "
    echo " "
    echo " "
    echo " "
    echo "-------------------------------------------------------------------------------"
    echo "                    INTERNET COMPUTER SETUP WAS SUCCESSFUL"
    echo "-------------------------------------------------------------------------------"
    echo " "
    echo " "
    echo " "
    echo " "
    echo "          Please do NOT unplug the Nitrokey HSM USB device just yet."
    echo " "
    echo "                 Wait for the message after the first boot..."
    echo " "
    echo " "
    echo " "
    echo " "
    echo "-------------------------------------------------------------------------------"
    echo "                    INTERNET COMPUTER SETUP WAS SUCCESSFUL"
    echo "-------------------------------------------------------------------------------"
    echo " "
    echo " "
    echo " "
    echo " "
    sleep 15
    shutdown -r now
}

# Establish run order
main() {
    source /media/cdrom/nocloud/00_common.sh
    log_start
    reboot_setupos
    log_end
}

main
