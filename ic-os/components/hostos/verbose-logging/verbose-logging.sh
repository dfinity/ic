#!/bin/bash

source /opt/ic/bin/config.sh
source /opt/ic/bin/logging.sh

verbose=$(get_config_value '.hostos_settings.verbose')

if [[ "${verbose,,}" == "true" ]]; then
    echo "##########################################" >/dev/tty1
    echo "###  STARTING GUESTOS CONSOLE LOGS...  ###" >/dev/tty1
    echo "##########################################" >/dev/tty1

    COUNT=$(get_guest_vm_count)

    # Log slowly so as not to overwhelm the host terminal, scaled by the number
    # of VMs so the combined line rate stays the same.
    DELAY_MS=$((75 * COUNT))
    DELAY=$(printf '%d.%03d' $((DELAY_MS / 1000)) $((DELAY_MS % 1000)))

    for i in $(seq 1 "${COUNT}"); do
        s=$(get_guest_vm_suffix "$i" "$COUNT")

        tail -f "/var/log/libvirt/qemu/guestos-serial$s.log" | sanitize_output | while IFS= read -r line; do
            printf 'guestos-serial%s| %s\n' "$s" "$line" >/dev/tty1
            sleep "${DELAY}"
        done &
    done

    wait
fi
