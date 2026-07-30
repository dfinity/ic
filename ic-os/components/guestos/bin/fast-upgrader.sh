#!/usr/bin/env bash
#
# Fast upgrader: applies a SquashFS overlay via systemd-sysext and restarts
# the services listed in the overlay's restart.list metadata.
#
# Supports sequential upgrades: unmerges any previous overlay before applying
# the new one.
#
# Usage: fast-upgrader.sh --version <replica_version>
#
# TODO(phase1): health monitoring (certified height must advance within TIMEOUT).
# TODO(phase1): rollback on failure (systemd-sysext unmerge + restart old services).

set -euo pipefail

VERSION=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    echo "Error: --version is required"
    exit 1
fi

EXTENSION_DIR="/var/lib/extensions"
EXTENSION_NAME="ic-upgrade.raw"
OVERLAY_SRC="/var/upgrades/overlay.raw"

if [[ ! -f "$OVERLAY_SRC" ]]; then
    echo "Error: overlay image ${OVERLAY_SRC} not found"
    exit 1
fi

echo "Phase 1 fast upgrade to ${VERSION}"

# 1. Remove any previous overlay (supports sequential upgrades — idempotent).
echo "Removing previous overlay..."
systemd-sysext unmerge 2>/dev/null || true
rm -f "${EXTENSION_DIR}/${EXTENSION_NAME}"

# 2. Install the new overlay.
echo "Installing overlay..."
mkdir -p "${EXTENSION_DIR}"
cp "$OVERLAY_SRC" "${EXTENSION_DIR}/${EXTENSION_NAME}"
systemd-sysext refresh

# 3. Read restart.list and restart only the listed services.
LIST_FILE="/opt/upgrade_metadata/restart.list"
if [[ -f "$LIST_FILE" ]]; then
    echo "Restarting services..."
    mapfile -t SERVICES < "$LIST_FILE"
    if [[ ${#SERVICES[@]} -gt 0 ]]; then
        systemctl try-restart "${SERVICES[@]}"
    fi
    echo "Upgrade complete. Restarted: ${SERVICES[*]}"
else
    echo "Warning: no restart.list found, services not restarted."
fi
