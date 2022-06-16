#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function log_and_reboot_on_error() {
    local exit_code="${1}"
    local log_message="${2}"

    if [ "${exit_code}" -ne 0 ]; then
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo " "
        echo "--------------------------------------------------------------------------------"
        echo "                       INTERNET COMPUTER - SETUP - FAILED"
        echo "--------------------------------------------------------------------------------"
        echo " "
        echo " "
        echo " "
        echo " "
        echo "          Please contact Internet Computer Association (ICA) support."
        echo " "
        echo " "
        echo " "
        echo " "
        echo "--------------------------------------------------------------------------------"
        echo "                                     ERROR"
        echo "--------------------------------------------------------------------------------"
        echo " "
        echo " "
        echo "${log_message}"
        echo " "
        echo " "
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
