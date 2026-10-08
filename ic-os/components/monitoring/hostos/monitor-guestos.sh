#!/bin/bash

set -e

# Monitor the GuestOS virtual machine.

source /opt/ic/bin/logging.sh
source /opt/ic/bin/metrics.sh
source /opt/ic/bin/config.sh

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
    node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

    case "${node_reward_type}" in
        type4.0) COUNT=32 ;;
        type4.1) COUNT=60 ;;
        type4.2) COUNT=8 ;;
        type4.3) COUNT=4 ;;
        type4.4) COUNT=2 ;;
        *) COUNT=1 ;;
    esac

    for i in $(seq 0 "$((COUNT - 1))"); do
        # A single GuestOS keeps the guestos name
        if [ "$COUNT" -eq 1 ]; then
            s=""
        else
            s=$i
        fi

        vm="guestos$s"

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
