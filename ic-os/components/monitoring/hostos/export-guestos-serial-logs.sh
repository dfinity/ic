#!/bin/bash

# Export GuestOS serial logs to journald

set -e

tail -F /var/log/libvirt/qemu/guestos-serial.log | systemd-cat -t guestos-serial -p info &
tail -F /var/log/libvirt/qemu/upgrade-guestos-serial.log | systemd-cat -t upgrade-guestos-serial -p info &
wait
