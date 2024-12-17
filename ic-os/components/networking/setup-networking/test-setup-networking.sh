#!/usr/bin/env bash

set -euo pipefail

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Create mock 'ip' command
cat >"${TEMP_DIR}/ip" <<'EOF'
#!/bin/bash
if [ "$1" = "-o" ] && [ "$2" = "link" ] && [ "$3" = "show" ]; then
    echo "1: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000"
    echo "2: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000"
    echo "3: eth2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000"
else
    # Pass through for any other calls (if any)
    /usr/bin/ip "$@"
fi
EOF
chmod +x "${TEMP_DIR}/ip"

# Create mock 'ethtool' command
cat >"${TEMP_DIR}/ethtool" <<'EOF'
#!/bin/bash
IFACE="$1"
case "$IFACE" in
    eth0) echo "Speed: 10000Mb/s" ;;
    eth1) echo "Speed: 1000Mb/s" ;;
    eth2) echo "Speed: 100Mb/s" ;;
    *) echo "Speed: Unknown" ;;
esac
EOF
chmod +x "${TEMP_DIR}/ethtool"

# Source the original script
source ./setup-networking.sh

# Update PATH so that our mocks are used
export PATH="${TEMP_DIR}:$PATH"
# Clear any cached command lookups
hash -r

# We just call gather_interfaces_by_speed and check results.
gather_interfaces_by_speed

# Expected order (descending by speed) is: eth0, eth1, eth2
EXPECTED_INTERFACES="eth0,eth1,eth2"

if [ "${INTERFACE_LIST}" = "${EXPECTED_INTERFACES}" ]; then
    echo "Test passed: Interfaces sorted correctly."
    exit 0
else
    echo "Test failed: Expected ${EXPECTED_INTERFACES}, got ${INTERFACE_LIST}"
    exit 1
fi
