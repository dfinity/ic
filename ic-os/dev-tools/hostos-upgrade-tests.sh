#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IC_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REVISIONS_FILE="${IC_ROOT}/mainnet-icos-revisions.json"

# List of HostOS versions to test upgrades *from*
# Note: doing more than 3 versions at a time may cause the devenv to run out of space
# Note: for older versions, you may have to update the setupos-image-config
# and setupos-disable-checks tools to to be compatible
VERSIONS=(
    "version1"
    "version2"
)

bazel clean --expunge

declare -A results

for version in "${VERSIONS[@]}"; do
    echo "==================================="
    echo "Testing HostOS version: $version"
    echo "==================================="

    tmpfile=$(mktemp)
    url="https://download.dfinity.systems/ic/${version}/host-os/update-img/update-img.tar.zst"

    echo "Downloading update image from $url ..."
    if ! curl -fL -o "$tmpfile" "$url"; then
        echo "Failed to download update image for version $version."
        results["$version"]="Download failed"
        rm -f "$tmpfile"
        continue
    fi

    hash=$(sha256sum "$tmpfile" | awk '{print $1}')
    echo "Calculated update_img_hash: $hash"
    rm -f "$tmpfile"

    # Update the mainnet-icos-revisions.json file with the current version and computed hash.
    if ! jq --arg ver "$version" --arg hash "$hash" \
        '.hostos.latest_release.version = $ver | .hostos.latest_release.update_img_hash = $hash' \
        "$REVISIONS_FILE" >"${REVISIONS_FILE}.tmp"; then
        echo "Failed to update $REVISIONS_FILE for version $version."
        results["$version"]="JSON update failed"
        continue
    fi
    mv "${REVISIONS_FILE}.tmp" "$REVISIONS_FILE"
    echo "Updated $REVISIONS_FILE for version $version."

    echo "Running hostos_upgrade_from_latest_release_to_current test for version $version ..."
    if bazel test //rs/tests/nested:hostos_upgrade_from_latest_release_to_current; then
        echo "Test for version $version PASSED."
        results["$version"]="Passed"
    else
        echo "Test for version $version FAILED."
        results["$version"]="Failed"
    fi

    echo ""
done

echo "==================== Test Summary ===================="
for ver in "${!results[@]}"; do
    echo "Version $ver: ${results[$ver]}"
done
echo "======================================================="
