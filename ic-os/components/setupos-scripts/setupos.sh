#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function start_setupos() {
    # Wait until login prompt appears
    sleep 5
    clear
    echo "* Starting SetupOS..."
    echo -e "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
    echo "-------------------------------------------------------------------------------"
    echo "                           INTERNET COMPUTER - SETUP"
    echo "-------------------------------------------------------------------------------"
    echo -e "\n\n"
}

function reboot_setupos() {
    echo -e "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
    echo "          If a Nitrokey HSM USB device is in use, please do NOT unplug it just yet."
    echo -e "\n\n\n\n"
    echo "-------------------------------------------------------------------------------"
    echo "                    INTERNET COMPUTER - SETUP - SUCCESSFUL"
    echo "-------------------------------------------------------------------------------"
    echo -e "\n\n\n\n"
    echo "* Rebooting SetupOS..."
    echo -e "\n\n"
    sleep 15
    shutdown -r now
}

# Establish run order
main() {
    source /opt/ic/bin/functions.sh
    log_start "$(basename $0)"
    start_setupos
    /opt/ic/bin/check-setupos-age.sh
    /opt/ic/bin/hardware.sh
    /opt/ic/bin/network.sh
    /opt/ic/bin/disk.sh
    /opt/ic/bin/hostos.sh
    /opt/ic/bin/guestos.sh
    /opt/ic/bin/devices.sh
    reboot_setupos
    log_end "$(basename $0)"
}

main
