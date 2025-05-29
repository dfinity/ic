#!/bin/bash

set -e

# Completes the recovery process by downloading and applying the recovery artifacts

echo "Starting GuestOS recovery engine..."

trap 'popd > /dev/null 2>&1 || true' EXIT
mkdir -p /tmp/subnet_recovery
pushd /tmp/subnet_recovery > /dev/null

echo "Downloading recovery artifacts..."
local base_urls=(
    "https://download.dfinity.systems/"
    "https://download.dfinity.network/"
)
for base_url in "${base_urls[@]}"; do
    local registry_url="${base_url}ic_registry_local_store.tar.zst"
    local cup_url="${base_url}cup.proto"
    echo "Attempting to download recovery artifacts from $base_url"

    registry_success=false
    cup_success=false

    if curl -L -o "ic_registry_local_store.tar.zst" "$registry_url"; then
        echo "Successfully downloaded ic_registry_local_store.tar.zst from $base_url"
        registry_success=true
    else
        echo "WARNING: Failed to download ic_registry_local_store.tar.zst from $base_url"
        rm -f "ic_registry_local_store.tar.zst"
    fi

    if curl -L -o "cup.proto" "$cup_url"; then
        echo "Successfully downloaded cup.proto from $base_url"
        cup_success=true
    else
        echo "WARNING: Failed to download cup.proto from $base_url"
        rm -f "cup.proto"
    fi

    if [ "$registry_success" = true ] && [ "$cup_success" = true ]; then
        echo "Download from $base_url completed successfully"
        download_successful=true
        break
    else
        echo "WARNING: Failed to download all artifacts from $base_url"
        # Clean up partial downloads
        rm -f "ic_registry_local_store.tar.zst"
        rm -f "cup.proto"
    fi
done

if [ "$download_successful" = false ]; then
    echo "ERROR: Failed to download recovery artifacts from all available URLs"
    exit 1
fi

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
# TODO: discuss service restarts: we can either restart the ic-replica service here or have the service itself come before ic-replica.service
# sudo systemctl start ic-replica;
# sudo systemctl status ic-replica;

echo "GuestOS recovery engine completed"
