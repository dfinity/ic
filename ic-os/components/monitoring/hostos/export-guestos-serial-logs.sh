#!/bin/bash
set -euo pipefail

# Export GuestOS serial logs to journald
# Strip ANSI color/escape codes from serial console output before forwarding to journald

source /opt/ic/bin/config.sh
source /opt/ic/bin/guestos-vm-count.sh

slots=($(guestos_vm_slots))

# Forward all the GuestOS logs, and the upgrade VMs' too
for slot in "${slots[@]}"; do
    s=$(guestos_vm_slot_suffix "$slot")

    for name in "guestos-serial$s" "upgrade-guestos-serial$s"; do
        tail -F "/var/log/libvirt/qemu/$name.log" | sed --unbuffered 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t "$name" -p info &
    done
done

wait
