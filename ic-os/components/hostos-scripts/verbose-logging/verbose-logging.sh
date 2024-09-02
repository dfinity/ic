#!/bin/bash

CONFIG="${CONFIG:=/boot/config/config.ini}"

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "verbose") verbose="${value}" ;;
        esac
    done <"${CONFIG}"
}

read_variables

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
