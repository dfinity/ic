#!/bin/bash

source /opt/ic/bin/config.sh

verbose=$(get_config_value '.hostos_settings.verbose')

if [[ "${verbose,,}" == "true" ]]; then
    echo "##########################################" >/dev/tty1
    echo "###  STARTING GUESTOS CONSOLE LOGS...  ###" >/dev/tty1
    echo "##########################################" >/dev/tty1

    # One log per VM slot, unsuffixed on a single-GuestOS node. Follow only the
    # first; wait for it, since libvirt creates the logs after guestos.target.
    log=""
    while [ -z "$log" ]; do
        for candidate in /var/log/libvirt/qemu/guestos-serial.log \
            /var/log/libvirt/qemu/guestos-serial[0-9]*.log; do
            if [ -f "$candidate" ]; then
                log="$candidate"
                break
            fi
        done
        [ -n "$log" ] || sleep 5
    done

    # log slowly so as not to overwhelm the host terminal
    tail -F "$log" | while read -r line; do
        echo "$line" >/dev/tty1
        sleep 0.075
    done
fi
