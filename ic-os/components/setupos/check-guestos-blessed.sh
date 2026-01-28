#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

# Check if the GuestOS version is blessed in the NNS registry.
function check_guestos_blessed() {
    local sev_enabled
    sev_enabled=$(get_config_value '.icos_settings.enable_trusted_execution_environment')

    echo "* Checking if GuestOS version is blessed in NNS registry..."

    if /opt/ic/bin/setupos_tool check-blessed-version; then
        echo "* GuestOS version is blessed."
        return 0
    fi

    # Version is not blessed
    if [[ "${sev_enabled}" == "true" ]]; then
        echo -e "\n\n\n\n\n\n"
        echo -e "\033[1;31mWARNING: GuestOS version is NOT blessed in the NNS registry!\033[0m"
        echo -e "\033[1;31mThis node will NOT be able to join the IC network.\033[0m"
        echo -e "\033[1;31mPlease download the latest IC-OS release from the Internet Computer Dashboard Releases page!\033[0m"
        echo -e "\n\n\n"
        echo "Pausing for 10 minutes before continuing installation..."
        sleep 600
    else
        echo -e "\033[1;33mNOTE: GuestOS version is not blessed in the NNS registry.\033[0m"
        echo "SEV is disabled, so this is just a warning. Continuing installation..."
    fi
}

main() {
    log_start "$(basename $0)"
    if check_cmdline_var ic.setupos.run_checks; then
        check_guestos_blessed
    else
        echo "* GuestOS blessed version check skipped by request via kernel command line"
    fi
    log_end "$(basename $0)"
}

main
