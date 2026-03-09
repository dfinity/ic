#!/bin/bash

# Export GuestOS serial logs to journald

set -e

# Strip ANSI color/escape codes from serial console output before forwarding to journald
tail -F /var/log/libvirt/qemu/guestos-serial.log | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t guestos-serial -p info &
tail -F /var/log/libvirt/qemu/upgrade-guestos-serial.log | sed 's/\x1b\[[0-9;]*[a-zA-Z]//g; s/\[[0-9]\+;[0-9;]*m//g' | systemd-cat -t upgrade-guestos-serial -p info &
wait
