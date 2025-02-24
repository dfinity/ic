#!/usr/bin/env bash

set -euo pipefail

VERSION="$(git rev-parse HEAD)"

# PATH0
mkdir -p "$PATH0"
if ! curl -sfS --retry 5 --retry-delay 10 \
    "https://download.dfinity.systems/ic/$VERSION/$PATH0/SHA256SUMS" \
    -o "$PATH0/SHA256SUMS"; then

    # workaround until we have a better way to pass SHA256SUMS files around
    echo "Assuming artifacts were not rebuilt"
    exit 0
fi

# ignore *.wasm.gz.did files (these are checksummed by upload_artifacts but
# not by build-ic.sh)
sed -i -e '/.wasm.gz.did/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"

# for hostos / guestos we only care about update-img
sed -i -e '/disk-img/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"

if ! diff -u "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"; then
    echo "Build Determinism Check Failed!"
    echo "Contact IDX or investigate by yourself using diffoscope."
    exit 1
fi

echo "Build Determinism Check Successful"
