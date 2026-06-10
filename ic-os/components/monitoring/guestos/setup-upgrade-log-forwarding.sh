#!/bin/bash

set -euo pipefail

echo "Enabling journald serial console forwarding for Upgrade VM"
install -d /run/systemd/journald.conf.d
cat >/run/systemd/journald.conf.d/60-upgrade-vm-serial-output.conf <<'EOF'
[Journal]
ForwardToConsole=yes
TTYPath=/dev/ttyS0
MaxLevelConsole=debug
EOF
