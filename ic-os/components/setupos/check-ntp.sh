#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

# Needs a reachable NTP source, and specifically one of the NTS servers:
# `chrony.conf` pairs 14 NTS servers with two plain pool servers, and chrony's
# `authselectmode` defaults to `mix`, which marks the authenticated sources
# `require`d as soon as both kinds are configured -- so the clock is only ever
# synchronized from an NTS server. A hermetic test environment therefore cannot
# satisfy this check by standing up its own NTP server, however correct: it would
# have to serve NTS under one of those 14 hostnames, with a certificate the guest
# trusts. Hence the `ic.setupos.run_checks` gate in `main`, as for the other checks
# that need connectivity. Test VMs take their clock from the hypervisor anyway.
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
    if check_cmdline_var ic.setupos.run_checks; then
        check_ntp
    else
        echo "* NTP synchronization check skipped by request via kernel command line"
    fi
    set_hwclock_utc
    log_end "$(basename $0)"
}

main
