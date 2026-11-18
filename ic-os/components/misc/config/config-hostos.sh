#!/bin/bash

# Shared config utilities.

# Retrieves a value from the config.json file using a JSON path.
# Arguments:
#   $1 - JSON path to the desired value (e.g., '.icos_settings.nns_urls')
# Returns:
#   If key is not found or value is "null", returns empty string.
#   Otherwise, returns value.
function get_config_value() {
    local CONFIG_FILE="/boot/config/config.json"
    local key=$1

    local value=$(jq -r "${key}" "${CONFIG_FILE}")

    if [[ "${value}" == "null" ]]; then
        echo ""
    else
        echo "${value}"
    fi
}

function get_guest_vm_count() {
    local node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

    /opt/ic/bin/config_tool guest-vm-count --node-reward-type "${node_reward_type}"
}

# Mirrors VmSlot::to_suffix(). Args: slot, VM count.
function get_guest_vm_suffix() {
    local slot=$1
    local count=$2

    if ((count == 1)); then
        echo ""
    else
        echo "${slot}"
    fi
}
