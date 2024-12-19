#!/usr/bin/env bash

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <path-to-setup-networking.sh> <path-to-99-setup-netplan.yaml.template>"
    exit 1
fi

SETUP_SCRIPT="$1"
TEMPLATE_FILE="$2"

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

SHELL=/bin/bash

function mock_tools() {
    export SYS_NET_PATH="${TEST_DIR}/sys/class/net"
    mkdir -p "${SYS_NET_PATH}"
    mkdir -p "${TEST_DIR}/sys/devices/mock_devices/"
    ln -sf "${TEST_DIR}/sys/devices/mock_devices/" "${SYS_NET_PATH}/eth0"
    ln -sf "${TEST_DIR}/sys/devices/mock_devices/" "${SYS_NET_PATH}/eth1"
    ln -sf "${TEST_DIR}/sys/devices/mock_devices/" "${SYS_NET_PATH}/eth2"

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
    cat >"${TEST_DIR}/opt/ic/bin/setupos_tool" <<'EOF'
#!/bin/bash
if [ "$1" = "generate-mac-address" ]; then
    echo "02:00:00:aa:bb:cc"
elif [ "$1" = "generate-ipv6-address" ]; then
    echo "2001:db8::1234"
fi
EOF
    chmod +x "${TEST_DIR}/opt/ic/bin/setupos_tool"

    cat >"${TEST_DIR}/netplan" <<'EOF'
#!/bin/bash
if [ "$1" = "generate" ] || [ "$1" = "apply" ]; then
    exit 0
fi
EOF
    chmod +x "${TEST_DIR}/netplan"

    mkdir -p "${TEST_DIR}/var/ic/config"
    cat >"${TEST_DIR}/var/ic/config/config.ini" <<'EOF'
ipv6_gateway=fe80::2
EOF

    mkdir -p "${TEST_DIR}/run/netplan"
}

function test_gather_interfaces_by_speed() {
    export PATH="${TEST_DIR}:${PATH}"
    hash -r

    source "$SETUP_SCRIPT"
    gather_interfaces_by_speed
    local EXPECTED_INTERFACES="eth2,eth1,eth0"
    if [ "${INTERFACE_LIST}" = "${EXPECTED_INTERFACES}" ]; then
        echo "TEST PASSED: gather_interfaces_by_speed"
    else
        echo "TEST FAILED: gather_interfaces_by_speed"
        exit 1
    fi
}

function test_netplan_config() {
    export PATH="${TEST_DIR}:${PATH}"
    hash -r

    CONFIG_BASE_PATH="${TEST_DIR}/var/ic/config" \
        NETPLAN_TEMPLATE_PATH="$(dirname "$TEMPLATE_FILE")" \
        NETPLAN_RUN_PATH="${TEST_DIR}/run/netplan" \
        IC_BIN_PATH="${TEST_DIR}/opt/ic/bin" \
        SHELL=/bin/bash \
        /bin/bash "$SETUP_SCRIPT" SetupOS

    local OUTPUT_FILE="${TEST_DIR}/run/netplan/99-setup-netplan.yaml"

    [ -f "$OUTPUT_FILE" ] || {
        echo "Test failed: netplan output file not created"
        exit 1
    }
    grep -q "macaddress: 02:00:00:aa:bb:cc" "$OUTPUT_FILE" || {
        echo "Test failed: MAC address substitution"
        exit 1
    }
    grep -q "2001:db8::1234" "$OUTPUT_FILE" || {
        echo "Test failed: IPv6 address substitution"
        exit 1
    }
    grep -q "fe80::2" "$OUTPUT_FILE" || {
        echo "Test failed: IPv6 gateway substitution"
        exit 1
    }
    grep -Eq "interfaces:\s*\[eth2,eth1,eth0\]" "$OUTPUT_FILE" || {
        echo "Test failed: Interfaces insertion"
        exit 1
    }

    echo "TEST PASSED: netplan_config"
}

mock_tools
test_gather_interfaces_by_speed
test_netplan_config

echo "All tests passed."
exit 0
