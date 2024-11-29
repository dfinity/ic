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

function _kernel_cmdline_bool() {
    local parm=
    local default="$1"
    local target_parameter="$2"
    local cmdline=()
    if [[ -v TEST_CMDLINE ]]; then
        local cmdline_file="${TEST_CMDLINE}"
    else
        local cmdline_file=/proc/cmdline
    fi

    # Read the command line values, parsed as quoted strings.
    while IFS= read -r -d '' parm; do
        cmdline+=("$parm")
    done < <(xargs printf '%s\0' <"${cmdline_file}")

    for parameter in "${cmdline[@]}"; do
        case "$parameter" in
            "$target_parameter" | "${target_parameter}=1")
                return 0 # True
                ;;
            "${target_parameter}=0")
                return 1 # False
                ;;
        esac
    done

    # Return based on the default value.
    if [[ "$default" == "true" ]]; then
        return 0 # True
    else
        return 1 # False
    fi
}

# Check if a kernel command line boolean is set to 1 (true).
# If set to 1, return true (0).
# If set to 0, return false (1).
# if absent or any other value, return true (0).
function kernel_cmdline_bool_default_true() {
    _kernel_cmdline_bool "true" "$1"
}

# Check if a kernel command line boolean is set to 1 (true).
# If set to 1, return true (0).
# If set to 0, return false (1).
# if absent or any other value, return false (1).
function kernel_cmdline_bool_default_false() {
    _kernel_cmdline_bool "false" "$1"
}
