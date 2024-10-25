#!/bin/bash

# Shared config utilities.

# Retrieves a value from the config.json file using a JSON path.
# Arguments:
#   $1 - JSON path to the desired value (e.g., '.icos_settings.nns_urls')
# Note: If the key is not found, this function will return null.
function get_config_value() {
    local CONFIG_FILE="/var/ic/config/config.json"
    local key=$1
    jq -r "${key}" "${CONFIG_FILE}"
}
