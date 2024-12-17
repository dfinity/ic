#!/usr/bin/env bash

set -euo pipefail

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "${TEST_DIR}/run/netplan"
mkdir -p "${TEST_DIR}/opt/ic/bin"
mkdir -p "${TEST_DIR}/boot/config"
mkdir -p "${TEST_DIR}/var/ic/config"

cat > "${TEST_DIR}/var/ic/config/config.ini" <<'EOF'
ipv6_gateway=fe80::2
EOF

# Mock ip and ethtool
cat > "${TEST_DIR}/ip" <<'EOF'
#!/bin/bash
if [ "$1" = "-o" ] && [ "$2" = "link" ] && [ "$3" = "show" ]; then
    echo "1: ethA: <BROADCAST,MULTICAST,UP> mtu 1500"
    echo "2: ethB: <BROADCAST,MULTICAST> mtu 1500"
else
    /usr/bin/ip "$@"
fi
EOF
chmod +x "${TEST_DIR}/ip"

cat > "${TEST_DIR}/ethtool" <<'EOF'
#!/bin/bash
IFACE="$1"
case "$IFACE" in
    ethA) echo "Speed: 10000Mb/s" ;;
    ethB) echo "Speed: 1000Mb/s" ;;
    *) echo "Speed: Unknown" ;;
esac
EOF
chmod +x "${TEST_DIR}/ethtool"

# Mock address generation tools
cat > "${TEST_DIR}/opt/ic/bin/setupos_tool" <<'EOF'
#!/bin/bash
if [ "$1" = "generate-mac-address" ]; then
    echo "02:00:00:aa:bb:cc"
elif [ "$1" = "generate-ipv6-address" ]; then
    echo "2001:db8::1234"
fi
EOF
chmod +x "${TEST_DIR}/opt/ic/bin/setupos_tool"

cat > "${TEST_DIR}/opt/ic/bin/hostos_tool" <<'EOF'
#!/bin/bash
if [ "$1" = "generate-mac-address" ]; then
    echo "02:00:00:dd:ee:ff"
elif [ "$1" = "generate-ipv6-address" ]; then
    echo "2001:db8::5678"
fi
EOF
chmod +x "${TEST_DIR}/opt/ic/bin/hostos_tool"

# Mock netplan
cat > "${TEST_DIR}/netplan" <<'EOF'
#!/bin/bash
if [ "$1" = "generate" ] || [ "$1" = "apply" ]; then
    exit 0
fi
EOF
chmod +x "${TEST_DIR}/netplan"

export PATH="${TEST_DIR}:${PATH}"
hash -r

# Test SetupOS mode using the template file in the current directory
CONFIG_BASE_PATH="${TEST_DIR}/var/ic/config" \
NETPLAN_TEMPLATE_PATH="." \
NETPLAN_RUN_PATH="${TEST_DIR}/run/netplan" \
IC_BIN_PATH="${TEST_DIR}/opt/ic/bin" \
SHELL=/bin/bash \
/bin/bash ./setup-networking.sh SetupOS

OUTPUT_FILE="${TEST_DIR}/run/netplan/99-setup-netplan.yaml"
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Test failed: Output file not created for SetupOS."
    exit 1
fi

grep -q "macaddress: 02:00:00:aa:bb:cc" "$OUTPUT_FILE" || { echo "Test failed: MAC address not substituted correctly for SetupOS."; exit 1; }
grep -q "2001:db8::1234" "$OUTPUT_FILE" || { echo "Test failed: IPv6 address not substituted correctly for SetupOS."; exit 1; }
grep -q "fe80::2" "$OUTPUT_FILE" || { echo "Test failed: IPv6 gateway not substituted correctly for SetupOS."; exit 1; }
grep -q "interfaces: ethA,ethB" "$OUTPUT_FILE" || { echo "Test failed: Interfaces not inserted correctly for SetupOS."; exit 1; }

echo "Test passed: Netplan output file produced correctly for SetupOS."
