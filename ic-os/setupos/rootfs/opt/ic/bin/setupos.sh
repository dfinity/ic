#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function start_setupos() {
    echo "* Starting SetupOS..."
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo "-------------------------------------------------------------------------------"
    echo "                           INTERNET COMPUTER - SETUP"
    echo "-------------------------------------------------------------------------------"
    echo " "
    echo " "
}

function reboot_setupos() {
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
    echo " "
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
    echo "                    INTERNET COMPUTER - SETUP - SUCCESSFUL"
    echo "-------------------------------------------------------------------------------"
    echo " "
    echo " "
    echo " "
    echo " "
    echo "* Rebooting SetupOS..."
    echo " "
    sleep 15
    shutdown -r now
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    # Wait until login prompt appears
    sleep 10
    start_setupos
    /opt/ic/bin/hardware.sh
    # NOTE: Firmware up-/downgrades are currently applied manually
    #/opt/ic/bin/firmware.sh
    # NOTE: UEFI settings are currently applied manually
    #/opt/ic/bin/uefi.sh
    /opt/ic/bin/disk.sh
    /opt/ic/bin/hostos.sh
    /opt/ic/bin/guestos.sh
    /opt/ic/bin/devices.sh
    reboot_setupos
    log_end "$(basename $0)"
}

main
