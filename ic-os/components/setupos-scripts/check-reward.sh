#!/usr/bin/env bash

set -o nounset
set -o pipefail

SHELL="/bin/bash"
PATH="/sbin:/bin:/usr/sbin:/usr/bin"

source /opt/ic/bin/functions.sh

CONFIG="${CONFIG:=/var/ic/config/config.ini}"

function read_variables() {
    # Read limited set of keys. Be extra-careful quoting values as it could
    # otherwise lead to executing arbitrary shell code!
    while IFS="=" read -r key value; do
        case "$key" in
            "node_reward_type") node_reward_type="${value}" ;;
        esac
    done <"${CONFIG}"
}

function validate_node_reward() {
    if [[ -z "$node_reward_type" ]]; then
        log_and_halt_installation_on_error 1 "Configuration error: node_reward_type is not set"
    fi

    if [[ ! "$node_reward_type" =~ ^type[0-9]+(\.[0-9])?$ ]]; then
        log_and_halt_installation_on_error 1 "Configuration error: node_reward_type is invalid: ${node_reward_type}"
    fi

    echo "Valid node reward type: ${node_reward_type}"
}

# Establish run order
main() {
    log_start "$(basename $0)"
    read_variables
    validate_node_reward
    log_end "$(basename $0)"
}

main
