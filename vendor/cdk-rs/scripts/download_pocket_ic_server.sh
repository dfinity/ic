#!/bin/bash

set -euo pipefail

uname_sys=$(uname -s | tr '[:upper:]' '[:lower:]')
echo "uname_sys: $uname_sys"

SCRIPTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPTS_DIR/../e2e-tests"
# extract the tag from e2e-tests/Cargo.toml
tag=$(grep -E 'pocket-ic.*tag' Cargo.toml | sed -n "s/.*tag *= *\"\([^\"]*\)\".*/\1/p")

ARTIFACTS_DIR="$SCRIPTS_DIR/../target/e2e-tests-artifacts"
mkdir -p "$ARTIFACTS_DIR"
cd "$ARTIFACTS_DIR"
echo -n "$tag" > pocket-ic-tag
curl -sL "https://github.com/dfinity/ic/releases/download/$tag/pocket-ic-x86_64-$uname_sys.gz" --output pocket-ic.gz
gzip -df pocket-ic.gz
chmod a+x pocket-ic
./pocket-ic --version

if [[ "$uname_sys" == "darwin" ]]; then
    xattr -dr com.apple.quarantine pocket-ic
fi
