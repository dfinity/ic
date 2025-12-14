#!/bin/bash
set -e

# Wrapper script to launch the guestos-recovery-upgrader with hardened systemd-run restrictions.
# This script is intended to be run by limited-console via sudo.

validate_argument() {
    local arg="$1"
    # Only allow known parameters with hexadecimal values
    # NOTE: version=RECOVERY_VERSION is allowed as a dummy value for testing purposes.
    if [[ "$arg" =~ ^version=[a-f0-9]{40}$ ]] \
        || [[ "$arg" == "version=RECOVERY_VERSION" ]] \
        || [[ "$arg" =~ ^version-hash=[a-f0-9]{64}$ ]] \
        || [[ "$arg" =~ ^recovery-hash=[a-f0-9]{64}$ ]]; then
        return 0
    else
        echo "ERROR: Invalid argument format: $arg" >&2
        return 1
    fi
}

if [ $# -eq 0 ]; then
    echo "Usage: $0 version=<version> version-hash=<hash> recovery-hash=<hash>"
    exit 1
fi

for arg in "$@"; do
    if ! validate_argument "$arg"; then
        echo "Arguments must be: version=<40-char-hex> version-hash=<64-char-hex> recovery-hash=<64-char-hex>"
        exit 1
    fi
done

exec /usr/bin/systemd-run \
    --unit=guestos-recovery-upgrader \
    --description="Manual GuestOS Recovery Upgrade" \
    --property=Type=oneshot \
    --property="CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_SYS_RESOURCE CAP_CHOWN CAP_FOWNER" \
    --property="AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_SYS_RESOURCE" \
    --property=ProtectSystem=strict \
    --property="ReadWritePaths=/dev /run /tmp /var/log" \
    --property=ProtectHome=yes \
    --property=PrivateTmp=yes \
    --property="RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" \
    --property=ProtectKernelModules=yes \
    --property=ProtectKernelTunables=yes \
    --property=ProtectKernelLogs=yes \
    --property=ProtectClock=yes \
    --property=LockPersonality=yes \
    --property=NoNewPrivileges=yes \
    --property=RestrictNamespaces=yes \
    --property=RestrictRealtime=yes \
    --property=RestrictSUIDSGID=yes \
    --property=ProtectControlGroups=yes \
    --property=ProtectHostname=yes \
    --property=SyslogIdentifier=guestos-recovery-upgrader \
    --property="StartLimitBurst=10" \
    --property="StartLimitIntervalSec=3600" \
    --property=TimeoutStartSec=1800 \
    --wait --pipe --collect -- \
    /opt/ic/bin/guestos-recovery-upgrader.sh "$@"
