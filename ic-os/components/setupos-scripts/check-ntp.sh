#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

function set_hwclock_utc() {
    echo "* Setting hardware clock to UTC..."
    timedatectl set-local-rtc 0
}

function check_ntp() {
    echo "* Checking Chrony status..."

    systemctl is-active --quiet chrony
    log_and_halt_installation_on_error "$?" "Chrony service not running or not active."

    if [ "$(timedatectl show -p NTPSynchronized --value)" != "yes" ]; then
        local service_logs=$(journalctl -u chrony.service --no-pager)
        local log_message="System clock is not synchronized. Please check NTP configuration.\n\nChrony service logs:\n${service_logs}"
        log_and_halt_installation_on_error 1 "${log_message}"
    fi

    echo "* Chrony is running and time is in sync."
}

main() {
    log_start "$(basename $0)"
    set_hwclock_utc
    check_ntp
    log_end "$(basename $0)"
}

main
