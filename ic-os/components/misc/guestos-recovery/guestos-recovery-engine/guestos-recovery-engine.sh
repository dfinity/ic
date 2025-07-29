#!/bin/bash

set -e

readonly EXPECTED_RECOVERY_HASH=""

# Completes the recovery process by downloading and applying the recovery artifacts

echo "Starting GuestOS recovery engine..."

trap 'popd > /dev/null 2>&1 || true' EXIT
mkdir -p /tmp/subnet_recovery
pushd /tmp/subnet_recovery >/dev/null

verify_file_hash() {
    local file="$1"
    local expected_hash="$2"
    local actual_hash

    echo "Verifying hash for $file..."
    actual_hash=$(sha256sum "$file" | cut -d' ' -f1)

    if [ "$actual_hash" = "$expected_hash" ]; then
        echo "✓ Hash verification successful for $file"
        return 0
    else
        echo "✗ Hash verification failed for $file"
        echo "  Expected: $expected_hash"
        echo "  Actual:   $actual_hash"
        return 1
    fi
}

download_recovery_artifact() {
    local base_url="$1"
    local recovery_url="${base_url}/ic/${EXPECTED_RECOVERY_HASH}/recovery.tar.zst"

    echo "Attempting to download recovery artifact from $recovery_url"

    if curl -L --fail -o "recovery.tar.zst" "$recovery_url"; then
        echo "Successfully downloaded recovery artifact from $base_url"
        return 0
    else
        echo "WARNING: Failed to download recovery artifact from $base_url"
        rm -f "recovery.tar.zst"
        return 1
    fi
}

echo "Downloading recovery artifact..."
base_urls=(
    "https://download.dfinity.systems"
    "https://download.dfinity.network"
)

download_successful=false
for base_url in "${base_urls[@]}"; do
    if download_recovery_artifact "$base_url"; then
        download_successful=true
        break
    fi
done

if [ "$download_successful" = false ]; then
    echo "ERROR: Failed to download recovery artifact from all available URLs"
    exit 1
fi

echo "Verifying recovery artifact..."
if ! verify_file_hash "recovery.tar.zst" "$EXPECTED_RECOVERY_HASH"; then
    echo "ERROR: Recovery artifact hash verification failed"
    exit 1
fi

echo "Recovery artifact verified successfully"

echo "Extracting recovery artifact..."
tar zxf "recovery.tar.zst"

echo "Preparing recovery artifacts..."
TARGET_PERMS=$(sudo stat -c '%a' /var/lib/ic/data/ic_registry_local_store)

mkdir ic_registry_local_store
tar zxf "ic_registry_local_store.tar.zst" -C ic_registry_local_store

OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/cups)
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/cups)
sudo chown -R "$OWNER_UID:$GROUP_UID" "cup.proto"

echo "Applying recovery artifacts..."
echo "Syncing ic_registry_local_store to target location..."
sudo rsync -a --delete ic_registry_local_store/ /var/lib/ic/data/ic_registry_local_store/
sudo chmod "$TARGET_PERMS" /var/lib/ic/data/ic_registry_local_store
echo "Copying cup.proto to target location..."
sudo cp "cup.proto" /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb

echo "Recovery artifacts applied successfully"

echo "Restarting services..."
sudo systemctl restart setup-permissions || true

echo "GuestOS recovery engine completed"
