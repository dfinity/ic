#!/usr/bin/env bash

set -eExuo pipefail

# bazel-targets file is expected from bazel-test-all CI job
if [ ! -e bazel-targets ]; then
    echo "Missing 'bazel-targets' file!"
    exit 1
fi

if grep -q "$TARGET" bazel-targets || grep -qF "//..." bazel-targets; then
    VERSION="$(git rev-parse HEAD)"

    # build-ic.tar with SHA256SUMS files is expected from build-ic CI job
    if [ ! -e build-ic.tar ]; then
        echo "Missing 'build-ic.tar' file!"
        exit 1
    fi

    # PATH0
    mkdir -p "$PATH0"
    curl -sfS --retry 5 --retry-delay 10 \
        "https://download.dfinity.systems/ic/$VERSION/$PATH0/SHA256SUMS" \
        -o "$PATH0/SHA256SUMS"

    # PATH1
    tar -xf build-ic.tar

    # ignore *.wasm.gz.did files
    sed -i -e '/.wasm.gz.did/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"
    # TODO(IDX): remove when issue is identified and addressed
    # https://gitlab.com/dfinity-lab/public/ic/-/snippets/3697069
    sed -i -e '/wasm.wasm.gz/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"
    # TODO(IDX): remove when issue is identified and addressed
    # https://gitlab.com/dfinity-lab/public/ic/-/snippets/3704313
    sed -i -e '/genesis-token-canister.wasm.gz/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"

    # for hostos / guestos we only care about update-img
    if [ "${DISKIMG:-}" != "true" ]; then
        sed -i -e '/disk-img/d' "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"
    fi

    if ! diff -u "$PATH0/SHA256SUMS" "$PATH1/SHA256SUMS"; then
        set -x
        cat build-ic/info
        echo "Build Determinism Check Failed!"
        echo "Contact IDX or investigate by yourself using diffoscope:"
        echo " * [bazel-test-all]: curl -sfS https://download.dfinity.systems/ic/$VERSION/$PATH0/<artifact> -O"
        echo " * [build-ic]: curl $(cat build-ic/url) -O"
        echo "See info for pull the artifacts from both CI jobs above. Specify <artifact> based on logs (e.g. 'ic-admin.gz', 'disk-img.tar.zst')."
        echo "Note that [build-ic] artifacts.tar contains all the build artifacts (binaries, canisters and IC images)."
        set +x
        exit 1
    else
        echo "Build Determinism Check Successful"
    fi
fi
