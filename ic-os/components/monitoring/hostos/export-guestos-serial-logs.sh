#!/bin/bash
set -euo pipefail

# Export GuestOS serial logs to journald
# Strip ANSI color/escape codes from serial console output before forwarding to journald

source /opt/ic/bin/config.sh

node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

case "${node_reward_type}" in
    type4.1) COUNT=60 ;;
    type4.2) COUNT=15 ;;
    type4.3) COUNT=4 ;;
    type4.4) COUNT=2 ;;
    *) COUNT=1 ;;
esac

# Slots match the units start-guestos.sh boots and VmSlot in
# guest_vm_config.rs: a single GuestOS runs in slot 0, multiple GuestOS run in
# slots 1..COUNT.
if [ "$COUNT" -eq 1 ]; then
    slots=(0)
else
    slots=($(seq 1 "$COUNT"))
fi

# Forward all the GuestOS logs
for slot in "${slots[@]}"; do
    # Slot 0, the single GuestOS, keeps the guestos-serial.log name
    if [ "$slot" -eq 0 ]; then
        s=""
    else
        s=$slot
    fi

    tail -F "/var/log/libvirt/qemu/guestos-serial$s.log" | sed --unbuffered 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t "guestos-serial$s" -p info &
done

# And the upgrade VMs
for slot in "${slots[@]}"; do
    # Slot 0, the single upgrade VM, keeps the upgrade-guestos-serial.log name
    if [ "$slot" -eq 0 ]; then
        s=""
    else
        s=$slot
    fi

    tail -F "/var/log/libvirt/qemu/upgrade-guestos-serial$s.log" | sed --unbuffered 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t "upgrade-guestos-serial$s" -p info &
done

wait
