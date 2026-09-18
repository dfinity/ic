#!/bin/bash

set -e

# Monitor the GuestOS virtual machine.

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/config.sh
source /opt/ic/bin/guestos-vm-count.sh

SCRIPT="$(basename $0)[$$]"

# Get keyword arguments
for argument in "${@}"; do
    case ${argument} in
        -h | --help)
            echo 'Usage:
Monitor GuestOS Virtual Machine

Arguments:
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

function monitor_guestos() {
    slots=($(guestos_vm_slots))

    for slot in "${slots[@]}"; do
        vm="guestos$(guestos_vm_slot_suffix "$slot")"

        if ! virsh list --all --name | grep -Fxq "$vm"; then
            write_log "ERROR: GuestOS virtual machine ${vm} is not defined."
            write_metric_attr "hostos_guestos_state" \
                "{vm=\"$vm\"}" \
                "1" \
                "GuestOS virtual machine state" \
                "gauge"

            # Avoid writing the "not running"  metric below
            continue
        fi

        if virsh list --state-running --name | grep -Fxq "$vm"; then
            write_metric_attr "hostos_guestos_state" \
                "{vm=\"$vm\"}" \
                "0" \
                "GuestOS virtual machine state" \
                "gauge"
        else
            write_log "GuestOS virtual machine ${vm} is not running."
            write_metric_attr "hostos_guestos_state" \
                "{vm=\"$vm\"}" \
                "2" \
                "GuestOS virtual machine state" \
                "gauge"
        fi
    done
}

function main() {
    # Establish run order
    monitor_guestos
}

main
