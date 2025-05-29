#!/bin/bash

source /opt/ic/bin/config.sh

verbose=$(get_config_value '.hostos_settings.verbose')

if [[ "${verbose,,}" == "true" ]]; then
    echo "##########################################" >/dev/tty1
    echo "###  STARTING GUESTOS CONSOLE LOGS...  ###" >/dev/tty1
    echo "##########################################" >/dev/tty1

    # log slowly so as not to overwhelm the host terminal
    tail -f /var/log/libvirt/qemu/guestos-serial.log | while read -r line; do
        echo "$line" >/dev/tty1
        sleep 0.075
    done
fi
