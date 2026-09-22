#!/bin/bash
set -euo pipefail

# Export GuestOS serial logs to journald
# Strip ANSI color/escape codes from serial console output before forwarding to journald

source /opt/ic/bin/config.sh
source /opt/ic/bin/guestos-vm-count.sh

slots=($(guestos_vm_slots))

forward_serial_log() {
    local name="$1"

    tail -F "/var/log/libvirt/qemu/$name.log" | sed --unbuffered 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t "$name" -p info &
}

# One GuestOS per slot the node boots
for slot in "${slots[@]}"; do
    forward_serial_log "guestos-serial$(guestos_vm_slot_suffix "$slot")"
done

# upgrade-guestos.service runs without --slot, so the upgrade VM is always the
# unsuffixed one, however many GuestOS the node runs.
forward_serial_log "upgrade-guestos-serial"

wait
