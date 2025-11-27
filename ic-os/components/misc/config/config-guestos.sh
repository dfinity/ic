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
