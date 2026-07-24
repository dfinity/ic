#!/bin/bash
set -euo pipefail

# This script dynamically starts guestos services to create the right number of VMs per node type

source /opt/ic/bin/config.sh

node_reward_type=$(get_config_value '.icos_settings.node_reward_type')

case "${node_reward_type}" in
    type4.0) COUNT=32 ;;
    type4.1) COUNT=60 ;;
    type4.2) COUNT=8 ;;
    type4.3) COUNT=4 ;;
    type4.4) COUNT=2 ;;
    *) COUNT=1 ;;
esac

# If not a type4 node, fall to the default GuestOS flow
if ((COUNT == 1)); then
    systemctl start guestos@0.service
    exit 0
fi

# TODO: Starting a ton of guests at once can lead to some of these units
# failing. For now, systemd will handle restarting them until they are healthy.
eval systemctl start --no-block guestos@{0..$((COUNT - 1))}.service
