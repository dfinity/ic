#!/usr/bin/env bash

set -euo pipefail

TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT

mkdir -p "${TEST_DIR}/run/netplan"
mkdir -p "${TEST_DIR}/opt/ic/share"
mkdir -p "${TEST_DIR}/boot/config"
mkdir -p "${TEST_DIR}/var/ic/config"
mkdir -p "${TEST_DIR}/opt/ic/bin"

# Mock config files
cat > "${TEST_DIR}/boot/config/config.ini" <<'EOF'
ipv6_gateway=fe80::1
EOF

cat > "${TEST_DIR}/var/ic/config/config.ini" <<'EOF'
ipv6_gateway=fe80::2
EOF

# Use the netplan template yaml file directly in the test
cat > "${TEST_DIR}/opt/ic/share/99-setup-netplan.yaml.template" <<'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    # Interfaces will be dynamically inserted here
  bonds:
    bond0:
      interfaces: {INTERFACES}
      parameters:
        mode: active-backup
        mii-monitor-interval: 5
        up-delay: 10000
        down-delay: 10000
      macaddress: {MAC_ADDRESS}
      mtu: 1500
      optional: true
  bridges:
    br6:
      interfaces: [bond0]
      addresses: [{IPV6_ADDR}]
      routes:
        - to: ::/0
          via: {IPV6_GATEWAY}
      nameservers:
        addresses: [2606:4700:4700::1111, 2606:4700:4700::1001, 2001:4860:4860::8888, 2001:4860:4860::8844]
      parameters:
        forward-delay: 0
        stp: false
      link-local: ["ipv6"]
      accept-ra: no
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

# Run SetupOS mode
CONFIG_BASE_PATH="${TEST_DIR}/var/ic/config" \
NETPLAN_TEMPLATE_PATH="${TEST_DIR}/opt/ic/share" \
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

# Run HostOS mode
CONFIG_BASE_PATH="${TEST_DIR}/boot/config" \
NETPLAN_TEMPLATE_PATH="${TEST_DIR}/opt/ic/share" \
NETPLAN_RUN_PATH="${TEST_DIR}/run/netplan" \
IC_BIN_PATH="${TEST_DIR}/opt/ic/bin" \
SHELL=/bin/bash \
/bin/bash ./setup-networking.sh HostOS

grep -q "macaddress: 02:00:00:dd:ee:ff" "$OUTPUT_FILE" || { echo "Test failed: MAC address not substituted correctly for HostOS."; exit 1; }
grep -q "2001:db8::5678" "$OUTPUT_FILE" || { echo "Test failed: IPv6 address not substituted correctly for HostOS."; exit 1; }
grep -q "fe80::1" "$OUTPUT_FILE" || { echo "Test failed: IPv6 gateway not substituted correctly for HostOS."; exit 1; }

echo "Test passed: Netplan output file produced correctly for both SetupOS and HostOS."
