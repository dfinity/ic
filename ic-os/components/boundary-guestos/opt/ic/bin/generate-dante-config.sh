#!/bin/bash
# Generate the network configuration from the information set in the
# configuration store.

set -euox pipefail

cat >/run/ic-node/etc/danted.conf <<EOF
# Configure logging
logoutput: stdout

# Interfaces to use
internal: enp1s0 port = 1080
external: enp1s0
$([[ -d /sys/class/net/enp2s0 ]] && echo "external: enp2s0" || echo "")

# Privileges
user.notprivileged: socks

# Don't require authentication
socksmethod: none
clientmethod: none

# Allow everyone - this is already restricted by nftables
client pass {
    from: ::0/0 to: ::0/0
    log: connect
}

socks pass {
    from: ::0/0 to: 0/0
}
EOF
