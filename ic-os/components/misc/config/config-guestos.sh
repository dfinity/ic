#!/bin/bash

# Shared config utilities.

# Retrieves a value from the config.json file using a JSON path.
# Arguments:
#   $1 - JSON path to the desired value (e.g., '.icos_settings.nns_urls')
# Returns:
#   If key is not found or value is "null", returns empty string.
#   Otherwise, returns value.
function get_config_value() {
    local CONFIG_FILE="/run/config/config.json"
    local key=$1

    local value=$(jq -r "${key}" "${CONFIG_FILE}")

    if [[ "${value}" == "null" ]]; then
        echo ""
    else
        echo "${value}"
    fi
}

# Returns success if running in an Upgrade VM, which does not open the encrypted
# store. Like maybe-disable-store-mounts.service, this treats every VM type
# other than "default" as such. init-config.service records the VM type, so
# this also returns success before it has run or if it failed.
function is_upgrade_vm() {
    [ ! -e /run/config/guest_vm_type/default ]
}
