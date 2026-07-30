#!/usr/bin/env bash
#
# Privileged wrapper invoked via sudo by the orchestrator to start the fast
# upgrader as an isolated transient systemd unit. The isolation is required
# because fast-upgrader.sh restarts ic-replica.service, which tears down the
# ic-replica.service cgroup (KillMode=control-group); running in its own unit
# keeps the script alive to complete the service restart.
#
# Running via sudo (as root) means the internal `systemd-run` talks to PID 1
# directly, bypassing polkit (which has no rules for the non-root ic-replica
# user and times out under SELinux).
#
# Only this wrapper is in the sudoers allowlist — not `systemd-run` itself —
# so the orchestrator cannot use sudo to start arbitrary transient units.
#
# Usage: run-fast-upgrader.sh <replica_version>
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <replica_version>" >&2
    exit 1
fi
VERSION="$1"

exec systemd-run --no-block --collect \
    --unit=fast-upgrader \
    /opt/ic/bin/fast-upgrader.sh --version "$VERSION"
