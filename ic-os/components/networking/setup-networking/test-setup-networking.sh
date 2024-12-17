#!/usr/bin/env bash

set -euo pipefail

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

SHELL=/bin/bash

function mock_tools() {
    cat >"${TEST_DIR}/ip" <<'EOF'
#!/bin/bash
if [ "$1" = "-o" ] && [ "$2" = "link" ] && [ "$3" = "show" ]; then
    echo "1: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000"
    echo "2: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000"
    echo "3: eth2: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000"
else
    /usr/bin/ip "$@"
fi
EOF
    chmod +x "${TEST_DIR}/ip"

    cat >"${TEST_DIR}/ethtool" <<'EOF'
#!/bin/bash
IFACE="$1"
case "$IFACE" in
    eth0) echo "Speed: 100Mb/s" ;;
    eth1) echo "Speed: 1000Mb/s" ;;
    eth2) echo "Speed: 10000Mb/s" ;;
    *) echo "Speed: Unknown" ;;
esac
EOF
    chmod +x "${TEST_DIR}/ethtool"

    mkdir -p "${TEST_DIR}/opt/ic/bin"
    cat > "${TEST_DIR}/opt/ic/bin/setupos_tool" <<'EOF'
#!/bin/bash
if [ "$1" = "generate-mac-address" ]; then
    echo "02:00:00:aa:bb:cc"
elif [ "$1" = "generate-ipv6-address" ]; then
    echo "2001:db8::1234"
fi
EOF
    chmod +x "${TEST_DIR}/opt/ic/bin/setupos_tool"

    cat > "${TEST_DIR}/netplan" <<'EOF'
#!/bin/bash
if [ "$1" = "generate" ] || [ "$1" = "apply" ]; then
    exit 0
fi
EOF
    chmod +x "${TEST_DIR}/netplan"

    mkdir -p "${TEST_DIR}/run/netplan"
    mkdir -p "${TEST_DIR}/boot/config"
    mkdir -p "${TEST_DIR}/var/ic/config"

    cat > "${TEST_DIR}/var/ic/config/config.ini" <<'EOF'
ipv6_gateway=fe80::2
EOF
}

function test_gather_interfaces_by_speed() {
    export PATH="${TEST_DIR}:${PATH}"
    hash -r

    source ./setup-networking.sh
    gather_interfaces_by_speed
    local EXPECTED_INTERFACES="eth2,eth1,eth0"
    if [ "${INTERFACE_LIST}" = "${EXPECTED_INTERFACES}" ]; then
        echo "Test passed: gather_interfaces_by_speed"
    else
        echo "Test failed: gather_interfaces_by_speed"
        exit 1
    fi
}

function test_netplan_config() {
    export PATH="${TEST_DIR}:${PATH}"
    hash -r

    CONFIG_BASE_PATH="${TEST_DIR}/var/ic/config" \
    NETPLAN_TEMPLATE_PATH="." \
    NETPLAN_RUN_PATH="${TEST_DIR}/run/netplan" \
    IC_BIN_PATH="${TEST_DIR}/opt/ic/bin" \
    SHELL=/bin/bash \
    /bin/bash ./setup-networking.sh SetupOS

    local OUTPUT_FILE="${TEST_DIR}/run/netplan/99-setup-netplan.yaml"

    [ -f "$OUTPUT_FILE" ] || { echo "Test failed: netplan output file not created"; exit 1; }
    grep -q "macaddress: 02:00:00:aa:bb:cc" "$OUTPUT_FILE" || { echo "Test failed: MAC address substitution"; exit 1; }
    grep -q "2001:db8::1234" "$OUTPUT_FILE" || { echo "Test failed: IPv6 address substitution"; exit 1; }
    grep -q "fe80::2" "$OUTPUT_FILE" || { echo "Test failed: IPv6 gateway substitution"; exit 1; }
    grep -Eq "interfaces:\s*\[eth2,eth1,eth0\]" "$OUTPUT_FILE" || { echo "Test failed: Interfaces insertion"; exit 1; }

    echo "Test passed: netplan_config"
}

mock_tools
test_gather_interfaces_by_speed
test_netplan_config

echo "All tests passed."
exit 0
