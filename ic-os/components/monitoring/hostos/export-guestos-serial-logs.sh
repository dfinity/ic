#!/bin/bash
set -euo pipefail

# Export GuestOS serial logs to journald
# Strip ANSI color/escape codes from serial console output before forwarding to journald

source /opt/ic/bin/config.sh
source /opt/ic/bin/logging.sh

COUNT=$(get_guest_vm_count)

# Slots are 1-based, and the suffix goes after `.log`. See serial_log_path().
for i in $(seq 1 "${COUNT}"); do
    s=$(get_guest_vm_suffix "$i" "$COUNT")

    tail -F "/var/log/libvirt/qemu/guestos-serial.log$s" | sanitize_output | systemd-cat -t "guestos-serial$s" -p info &
done

# And the upgrade VMs
for i in $(seq 1 "${COUNT}"); do
    s=$(get_guest_vm_suffix "$i" "$COUNT")

    tail -F "/var/log/libvirt/qemu/upgrade-guestos-serial.log$s" | sanitize_output | systemd-cat -t "upgrade-guestos-serial$s" -p info &
done

wait
