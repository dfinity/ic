#!/usr/bin/env bash

set -o nounset
set -o pipefail
set -e

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

trap 'handle_error $? $LINENO' ERR

function handle_error() {
    local exit_code="$1"
    local line="$2"
    log_and_halt_installation_on_error "$exit_code" "SetupOS encountered an error at line ${line}. Halting installation."
}

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
    log_start "$(basename $0)"
    start_setupos

    /opt/ic/bin/check-setupos-age.sh
    /opt/ic/bin/check-config.sh
    /opt/ic/bin/check-hardware.sh
    /opt/ic/bin/check-network.sh
    /opt/ic/bin/check-ntp.sh

    if kernel_cmdline_bool_default_true ic.setupos.perform_installation; then
        true
    else
        echo "* Installation skipped by request via kernel command line; stopping here"
        exit 0
    fi

    /opt/ic/bin/setup-disk.sh
    /opt/ic/bin/install-hostos.sh
    /opt/ic/bin/install-guestos.sh
    /opt/ic/bin/setup-hostos-config.sh

    if kernel_cmdline_bool_default_true ic.setupos.reboot_after_installation; then
        true
    else
        echo "* Reboot skipped by request via kernel command line; stopping here"
        exit 0
    fi

    reboot_setupos
    log_end "$(basename $0)"
}

main
