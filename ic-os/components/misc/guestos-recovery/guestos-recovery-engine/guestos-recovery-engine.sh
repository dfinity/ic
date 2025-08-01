#!/bin/bash

set -e

readonly EXPECTED_RECOVERY_HASH=""
readonly MAX_ATTEMPTS=10
readonly RETRY_DELAY=5

# Completes the recovery process by downloading and applying the recovery artifacts

echo "Starting GuestOS recovery engine with retry logic (max attempts: $MAX_ATTEMPTS, delay: ${RETRY_DELAY}s)..."

trap 'popd > /dev/null 2>&1 || true' EXIT
mkdir -p /tmp/subnet_recovery
pushd /tmp/subnet_recovery >/dev/null

perform_recovery() {
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
        return 1
    fi

    echo "Verifying recovery artifact..."
    if ! verify_file_hash "recovery.tar.zst" "$EXPECTED_RECOVERY_HASH"; then
        echo "ERROR: Recovery artifact hash verification failed"
        return 1
    fi

    echo "Recovery artifact verified successfully"

    echo "Extracting recovery artifact..."
    tar -xf "recovery.tar.zst"

    echo "Preparing recovery artifacts..."
    REGISTRY_PERMS=$(sudo stat -c '%a' /var/lib/ic/data/ic_registry_local_store)
    CUP_PERMS=$(sudo stat -c '%a' /var/lib/ic/data/cups)

    mkdir ic_registry_local_store
    tar -xf "ic_registry_local_store.tar.zst" -C ic_registry_local_store

    echo "Applying recovery artifacts..."
    echo "Syncing ic_registry_local_store to target location..."
    sudo rsync -a --delete ic_registry_local_store/ /var/lib/ic/data/ic_registry_local_store/
    sudo chmod "$REGISTRY_PERMS" /var/lib/ic/data/ic_registry_local_store
    echo "Copying cup.proto to target location..."
    sudo cp "cup.proto" /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb
    sudo chmod "$CUP_PERMS" /var/lib/ic/data/cups/cup.types.v1.CatchUpPackage.pb

    echo "Recovery artifacts applied successfully"

    echo "Restarting services..."
    sudo systemctl restart setup-permissions || true

    echo "GuestOS recovery engine completed successfully"
}

attempt=1
while [ $attempt -le $MAX_ATTEMPTS ]; do
    echo "=== Recovery attempt $attempt/$MAX_ATTEMPTS ==="

    if perform_recovery; then
        echo "✓ Recovery completed successfully on attempt $attempt"
        exit 0
    else
        echo "✗ Recovery failed on attempt $attempt"

        if [ $attempt -lt $MAX_ATTEMPTS ]; then
            echo "Waiting ${RETRY_DELAY} seconds before retry..."
            sleep $RETRY_DELAY
        fi
    fi

    ((attempt++))
done

echo "ERROR: Recovery failed after $MAX_ATTEMPTS attempts"
exit 1
