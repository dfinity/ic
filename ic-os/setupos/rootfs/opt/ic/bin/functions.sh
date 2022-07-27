#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function log_and_reboot_on_error() {
    local exit_code="${1}"
    local log_message="${2}"

    if [ "${exit_code}" -ne 0 ]; then
        echo -e "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
        echo "--------------------------------------------------------------------------------"
        echo "                       INTERNET COMPUTER - SETUP - FAILED"
        echo "--------------------------------------------------------------------------------"
        echo -e "\n\n\n\n"
        echo "        Please contact the Internet Computer Association (ICA) support."
        echo -e "\n\n\n\n"
        echo "--------------------------------------------------------------------------------"
        echo "                                     ERROR"
        echo "--------------------------------------------------------------------------------"
        echo -e "\n\n"
        echo "${log_message}"
        echo -e "\n\n"
        echo "--------------------------------------------------------------------------------"
        echo "                                     ERROR"
        echo "--------------------------------------------------------------------------------"
        sleep 120
        shutdown -h now
    fi
}

function log_start() {
    local script="${1}"
    TIME_START=$(date '+%s')

    echo "${script} - Start"
    log_and_reboot_on_error "${?}" "Unable to start '${script}' script."
    echo " "
}

function log_end() {
    local script="${1}"
    local time_end=$(date '+%s')
    local time_exec=$(expr "${time_end}" - "${TIME_START}")
    local time_hr=$(date -d "1970-01-01 ${time_exec} sec" '+%H:%M:%S')

    echo " "
    echo "${script} - End (${time_hr})"
    log_and_reboot_on_error "${?}" "Unable to end '${script}' script."
    echo " "
}

function detect_skew() {
    OEM=$(ipmitool mc info | sed -e 's/^Manufacturer ID[^0-9]*\([0-9]*\)/\1/' -e t -e d)
    log_and_reboot_on_error "${?}" "Unable to identify variant of machine."

    if [ "${OEM}" == "674" ]; then
        echo "dell"
    elif [ "${OEM}" == "10876" ]; then
        echo "supermicro"
    fi
}
