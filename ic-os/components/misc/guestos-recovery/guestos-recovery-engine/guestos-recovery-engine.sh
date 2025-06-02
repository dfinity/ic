#!/bin/bash

set -e

readonly EXPECTED_REGISTRY_HASH=""
readonly EXPECTED_CUP_HASH=""

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

download_artifacts_from_url() {
    local base_url="$1"
    local registry_url="${base_url}ic_registry_local_store.tar.zst"
    local cup_url="${base_url}cup.proto"

    echo "Attempting to download recovery artifacts from $base_url"

    # Download both artifacts - if either fails, the function fails
    if curl -L --fail -o "ic_registry_local_store.tar.zst" "$registry_url" \
        && curl -L --fail -o "cup.proto" "$cup_url"; then
        echo "Successfully downloaded recovery artifacts from $base_url"
        return 0
    else
        echo "WARNING: Failed to download recovery artifacts from $base_url"
        rm -f "ic_registry_local_store.tar.zst" "cup.proto"
        return 1
    fi
}

echo "Downloading recovery artifacts..."
base_urls=(
    "https://download.dfinity.systems/"
    "https://download.dfinity.network/"
)

download_successful=false
for base_url in "${base_urls[@]}"; do
    if download_artifacts_from_url "$base_url"; then
        download_successful=true
        break
    fi
done

if [ "$download_successful" = false ]; then
    echo "ERROR: Failed to download recovery artifacts from all available URLs"
    exit 1
fi

echo "Verifying recovery artifacts..."
if ! verify_file_hash "ic_registry_local_store.tar.zst" "$EXPECTED_REGISTRY_HASH"; then
    echo "ERROR: Registry artifact hash verification failed"
    exit 1
fi

if ! verify_file_hash "cup.proto" "$EXPECTED_CUP_HASH"; then
    echo "ERROR: CUP artifact hash verification failed"
    exit 1
fi

echo "All recovery artifacts verified successfully"

echo "Preparing recovery artifacts..."
OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/ic_registry_local_store)
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/ic_registry_local_store)

mkdir ic_registry_local_store
tar zxf "ic_registry_local_store.tar.zst" -C ic_registry_local_store
sudo chown -R "$OWNER_UID:$GROUP_UID" ic_registry_local_store

OWNER_UID=$(sudo stat -c '%u' /var/lib/ic/data/cups)
GROUP_UID=$(sudo stat -c '%g' /var/lib/ic/data/cups)
sudo chown -R "$OWNER_UID:$GROUP_UID" "cup.proto"

echo "Applying recovery artifacts..."
echo "Syncing ic_registry_local_store to target location..."
sudo rsync -a --delete ic_registry_local_store/ /var/lib/ic/data/ic_registry_local_store/
echo "Copying cup.proto to target location..."
sudo cp "cup.proto" /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb

echo "Recovery artifacts applied successfully"

echo "Restarting services..."
sudo systemctl restart setup-permissions || true

echo "GuestOS recovery engine completed"
