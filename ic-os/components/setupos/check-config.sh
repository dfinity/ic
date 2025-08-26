#!/usr/bin/env bash

# check-config.sh verifies the existence of the configuration JSON file created by config.service,
# halting the installation if not found.

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

check_config_file() {
    echo "* Checking Config..."
    local CONFIG_FILE="/var/ic/config/config.json"

    if [ -f "${CONFIG_FILE}" ]; then
        local config_contents=$(cat "${CONFIG_FILE}")
        echo -e "Configuration file '${CONFIG_FILE}' exists.\n"
        echo -e "File contents:\n${config_contents}"
    else
        local service_logs=$(journalctl -u config.service --no-pager)
        local log_message="Error creating SetupOS configuration. Configuration file '${CONFIG_FILE}' does not exist.\n\nConfig.service logs:\n${service_logs}"

        log_and_halt_installation_on_error 1 "${log_message}"
    fi
}

# Establish run order
main() {
    log_start "$(basename $0)"
    check_config_file
    log_end "$(basename $0)"
}

main
