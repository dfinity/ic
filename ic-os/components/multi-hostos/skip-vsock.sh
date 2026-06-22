#!/bin/bash

source /opt/ic/bin/config.sh

node_reward_type="$(get_config_value '.icos_settings.node_reward_type')"

if [[ "$node_reward_type" =~ ^type4(\.[0-9]+)?$ ]]; then
    echo "node_reward_type=${node_reward_type}; skipping vsock-agent"
    exit 1
fi

exit 0
