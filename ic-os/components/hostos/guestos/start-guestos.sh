#!/bin/bash
set -euo pipefail

# This script dynamically starts guestos services to create the right number of VMs per node type

source /opt/ic/bin/config.sh
source /opt/ic/bin/guestos-vm-count.sh

COUNT=$(guestos_vm_count)

# If not a type4 node, fall to the default GuestOS flow
if ((COUNT == 1)); then
    systemctl start guestos@0.service
    exit 0
fi

# TODO: Starting a ton of guests at once can lead to some of these units
# failing. For now, systemd will handle restarting them until they are healthy.
eval systemctl start --no-block guestos@{1..$((COUNT))}.service
