#!/bin/bash

set -e

# Start the GuestOS virtual machine.

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh

SCRIPT="$(basename $0)[$$]"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Start GuestOS virtual machine

Arguments:
  -c=, --config=        specify the GuestOS configuration file (Default: /var/lib/libvirt/guestos.xml)
  -h, --help            show this help message and exit
'
            exit 1
            ;;
        *)
            echo "Error: Argument is not supported."
            exit 1
            ;;
    esac
done

# Set arguments if undefined
CONFIG="${CONFIG:=/var/lib/libvirt/guestos.xml}"

write_tty1_log() {
    local message=$1

    echo "${SCRIPT} ${message}" >/dev/tty1

    logger -t "${SCRIPT}" "${message}"
}

function define_guestos() {
    if [ "$(virsh list --all | grep 'guestos')" ]; then
        write_log "GuestOS virtual machine is already defined."
        write_metric "hostos_guestos_service_define" \
            "0" \
            "GuestOS virtual machine define state" \
            "gauge"
    else
        write_log "Defining GuestOS virtual machine."
        virsh define ${CONFIG}
        write_metric "hostos_guestos_service_define" \
            "1" \
            "GuestOS virtual machine define state" \
            "gauge"
    fi
}

function start_guestos() {
    if [ "$(virsh list --state-running | grep 'guestos')" ]; then
        write_log "GuestOS virtual machine is already running."
        write_metric "hostos_guestos_service_start" \
            "0" \
            "GuestOS virtual machine start state" \
            "gauge"
    else
        write_log "Starting GuestOS virtual machine."
        # Attempt to start; if it fails, dump logs.
        if ! virsh start guestos; then
            # The sleep below gives QEMU time to clear the console so that
            # error messages won't be immediately overwritten.
            sleep 10

            write_tty1_log "ERROR: Failed to start GuestOS virtual machine."

            write_tty1_log "#################################################"
            write_tty1_log "###      LOGGING GUESTOS.SERVICE LOGS...      ###"
            write_tty1_log "#################################################"
            journalctl -u guestos.service >/dev/tty1

            write_tty1_log "#################################################"
            write_tty1_log "###          TROUBLESHOOTING INFO...          ###"
            write_tty1_log "#################################################"
            host_ipv6_address="$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type HostOS 2>/dev/null)"
            write_tty1_log "Host IPv6 address: $host_ipv6_address"

            if [ -f /var/log/libvirt/qemu/guestos-serial.log ]; then
                write_tty1_log "#################################################"
                write_tty1_log "###  LOGGING GUESTOS CONSOLE LOGS, IF ANY...  ###"
                write_tty1_log "#################################################"
                tail -n 30 /var/log/libvirt/qemu/guestos-serial.log | while IFS= read -r line; do
                    write_tty1_log "$line"
                done
            else
                write_tty1_log "No /var/log/libvirt/qemu/guestos-serial.log file found."
            fi

            write_tty1_log "Exiting start-guestos.sh so that systemd can restart guestos.service in 5 minutes."
            exit 1
        fi

        sleep 10
        write_tty1_log ""
        write_tty1_log "#################################################"
        write_tty1_log "GuestOS virtual machine launched"
        write_tty1_log "IF ONBOARDING, please wait for up to 10 MINUTES for a 'Join request successful!' message"
        host_ipv6_address="$(/opt/ic/bin/hostos_tool generate-ipv6-address --node-type HostOS 2>/dev/null)"
        write_tty1_log "Host IPv6 address: $host_ipv6_address"
        write_tty1_log "#################################################"

        write_log "Starting GuestOS virtual machine."
        write_metric "hostos_guestos_service_start" \
            "1" \
            "GuestOS virtual machine start state" \
            "gauge"
    fi
}

function main() {
    # Establish run order
    define_guestos
    start_guestos
}

main
