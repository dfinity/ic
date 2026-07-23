#!/bin/bash
set -euo pipefail

# Export GuestOS serial logs to journald
# Strip ANSI color/escape codes from serial console output before forwarding to journald

source /opt/ic/bin/config.sh

node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

case "${node_reward_type}" in
    type4.0) COUNT=32 ;;
    type4.1) COUNT=60 ;;
    type4.2) COUNT=8 ;;
    type4.3) COUNT=4 ;;
    type4.4) COUNT=2 ;;
    *) COUNT=1 ;;
esac

# Forward all the GuestOS logs
for i in $(seq 0 "$((COUNT - 1))"); do
    # A single GuestOS keeps the guestos-serial.log name
    if [ "$COUNT" -eq 1 ]; then
        s=""
    else
        s=$i
    fi

    tail -F "/var/log/libvirt/qemu/guestos-serial$s.log" | sed --unbuffered 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t "guestos-serial$s" -p info &
done

# And the upgrade VMs
for i in $(seq 0 "$((COUNT - 1))"); do
    # A single upgrade VM keeps the upgrade-guestos-serial.log name
    if [ "$COUNT" -eq 1 ]; then
        s=""
    else
        s=$i
    fi

    tail -F "/var/log/libvirt/qemu/upgrade-guestos-serial$s.log" | sed --unbuffered 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t "upgrade-guestos-serial$s" -p info &
done

wait
