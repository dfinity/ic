#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

function check_setupos_age() {
    if [ -f "/commit-time" ]; then
        six_weeks_ago=$(date -u -d '6 weeks ago' +%s)
        build_time=$(cat /commit-time)
        if [[ ${build_time} -lt ${six_weeks_ago} ]]; then
            echo -e "\n\n\n\n\n\n"
            echo -e "\033[1;31mWARNING: IC-OS installation image is more than six weeks out of date!\033[0m"
            echo -e "\033[1;31mPlease download the latest IC-OS release from the Internet Computer Dashboard Releases page!\033[0m"
            echo -e "\n\n\n"
            echo "Pausing for 10 minutes before continuing installation..."
            sleep 600
        fi
    fi
}

main() {
    log_start "$(basename $0)"
    if check_cmdline_var ic.setupos.run_checks; then
        check_setupos_age
    else
        echo "* SetupOS age check skipped by request via kernel command line"
    fi
    log_end "$(basename $0)"
}

main
