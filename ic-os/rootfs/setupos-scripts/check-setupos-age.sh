#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function check_setupos_age() {
    if [ -f "/build-time" ]; then
        six_weeks_ago=$(date -u -d '6 weeks ago' +%s)
        build_time=$(cat /build-time)
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
    check_setupos_age
}

main
