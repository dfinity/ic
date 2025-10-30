#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

function check_ntp() {
    echo "* Checking Chrony status..."

    systemctl is-active --quiet chrony
    log_and_halt_installation_on_error "$?" "Chrony service not running or not active."

    retries=0
    max_retries=30
    while [ "$(timedatectl show -p NTPSynchronized --value)" != "yes" ]; do
        if [ $retries -ge $max_retries ]; then
            local service_logs=$(journalctl -u chrony.service --no-pager)
            local sources_info=$(chronyc sources 2>/dev/null || echo "Unable to get chrony sources information")
            local log_message="System clock is not synchronized.\n\nChrony service logs:\n${service_logs}\n\nChrony sources status:\n${sources_info}"
            log_and_halt_installation_on_error 1 "${log_message}"
        fi

        echo "* Chrony not yet synchronized. Waiting 2 seconds before retry..."
        sleep 2
        ((retries++))
    done

    echo "* Chrony is running and time is in sync."
}

function set_hwclock_utc() {
    echo "* Setting hardware clock to UTC..."
    timedatectl set-local-rtc 0
}

main() {
    log_start "$(basename $0)"
    check_ntp
    set_hwclock_utc
    log_end "$(basename $0)"
}

main
