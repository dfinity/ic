#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/config.sh
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
        log_and_halt_installation_on_error "1" "GuestOS version is not blessed in the NNS registry (trusted execution is enabled)."
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
