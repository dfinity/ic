#!/bin/bash

source /opt/ic/bin/config.sh

verbose=$(get_config_value '.hostos_settings.verbose')

if [[ "${verbose,,}" == "true" ]]; then
    echo "##########################################" >/dev/tty1
    echo "###  STARTING GUESTOS CONSOLE LOGS...  ###" >/dev/tty1
    echo "##########################################" >/dev/tty1

    # A node running several GuestOS has one log per VM slot. Only the first is
    # followed, since interleaving all of them on tty1 would be unreadable.
    log="/var/log/libvirt/qemu/guestos-serial.log"
    for candidate in /var/log/libvirt/qemu/guestos-serial[0-9]*.log; do
        if [ -f "$candidate" ]; then
            log="$candidate"
            break
        fi
    done

    # log slowly so as not to overwhelm the host terminal
    tail -F "$log" | while read -r line; do
        echo "$line" >/dev/tty1
        sleep 0.075
    done
fi
