#!/bin/bash

# Shared config utilities.

# Retrieves a value from the config.json file using a JSON path.
# Arguments:
#   $1 - JSON path to the desired value (e.g., '.icos_settings.nns_urls')
# Returns:
    # If key not found or value is "null", returns empty string. Otherwise, returns value
function get_config_value() {
    local CONFIG_FILE="/var/ic/config/config.json"
    local key=$1
    jq -re "${key}" "${CONFIG_FILE}" 2>/dev/null || echo ""
}
