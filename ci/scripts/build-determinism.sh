#!/usr/bin/env bash

set -euo pipefail

VERSION="$(git rev-parse HEAD)"

# PATH0
mkdir -p "$PATH0"
curl -sfS --retry 5 --retry-delay 10 \
    "https://download.dfinity.systems/ic/$VERSION/$PATH0/SHA256SUMS" \
    -o "$PATH0/SHA256SUMS"

# TODO(IDX): remove when issue is identified and addressed
# https://gitlab.com/dfinity-lab/public/ic/-/snippets/3704313
sed -i -e '/genesis-token-canister.wasm.gz/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"

# for hostos / guestos we only care about update-img
sed -i -e '/disk-img/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"

if ! diff -u "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"; then
    cat build-ic/info
    echo "Build Determinism Check Failed!"
    echo "Contact IDX or investigate by yourself using diffoscope:"
    echo " * [bazel-test-all]: curl -sfS https://download.dfinity.systems/ic/$VERSION/$PATH0/<artifact> -O"
    echo " * [build-ic]: curl $(cat build-ic/url) -O"
    echo "See info for pull the artifacts from both CI jobs above. Specify <artifact> based on logs (e.g. 'ic-admin.gz', 'disk-img.tar.zst')."
    echo "Note that [build-ic] artifacts.tar contains all the build artifacts (binaries, canisters and IC images)."
    exit 1
fi

echo "Build Determinism Check Successful"
