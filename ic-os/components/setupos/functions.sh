#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

function log_and_halt_installation_on_error() {
    local exit_code="${1}"
    local log_message="${2}"

    if [ "${exit_code}" -ne 0 ]; then
        {
            # Sleep before printing error log to ensure previous log messages
            # have time to display on console (helpful for screen recordings).
            echo "ERROR DETECTED..."
            sleep 5

            echo -e "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
            echo "--------------------------------------------------------------------------------"
            echo "                       INTERNET COMPUTER - SETUP - FAILED"
            echo "--------------------------------------------------------------------------------"
            echo -e "\n\n"
            echo "        Please consult the wiki guide: Troubleshooting Node Deployment Errors."
            echo -e "\n\n"
            echo "--------------------------------------------------------------------------------"
            echo "                                     ERROR"
            echo "--------------------------------------------------------------------------------"
            echo -e "\n"
            echo -e "${log_message}"
            echo -e "\n"
            echo "--------------------------------------------------------------------------------"
            echo "                                     ERROR"
            echo "--------------------------------------------------------------------------------"
        } 1>&2
        sleep infinity
    fi
}

function log_start() {
    local script="${1}"
    TIME_START=$(date '+%s')

    echo "${script} - Start"
    log_and_halt_installation_on_error "${?}" "Unable to start '${script}' script."
    echo " "
}

function log_end() {
    local script="${1}"
    local time_end=$(date '+%s')
    local time_exec=$(expr "${time_end}" - "${TIME_START}")
    local time_hr=$(date -d "1970-01-01 ${time_exec} sec" '+%H:%M:%S')

    echo " "
    echo "${script} - End (${time_hr})"
    log_and_halt_installation_on_error "${?}" "Unable to end '${script}' script."
    echo " "
}

function find_first_drive() {
    if [ -e "/dev/vda" ]; then
        echo "vda"
        return 0
    fi

    lsblk -nld -o NAME,SIZE | grep 'T$' | grep -o '^\S*' | sort | head -n 1
}

function get_large_drives() {
    lsblk -nld -o NAME,SIZE | grep 'T$' | grep -o '^\S*'
}

# Returns true, unless the given var is explicitly turned off
function check_cmdline_var() {
    local target_var="$1"
    local cmdline_file="${2:-/proc/cmdline}"

    read -r -a cmdline <"$cmdline_file"
    for var in "${cmdline[@]}"; do
        if [ "$var" == "${target_var}=0" ]; then
            return 1 # False
        fi
    done

    return 0 # True
}
