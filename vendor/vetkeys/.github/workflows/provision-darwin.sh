#!/bin/bash

set -ex

# Enter temporary directory.
pushd /tmp

# Install Node.
brew install nodejs

# Install DFINITY SDK.
curl --location --output install-dfx.sh "https://raw.githubusercontent.com/dfinity/sdk/master/public/install-dfxvm.sh"
DFX_VERSION=${DFX_VERSION:=0.26.1} DFXVM_INIT_YES=true bash install-dfx.sh
rm install-dfx.sh
echo "$HOME/Library/Application Support/org.dfinity.dfx/bin" >> $GITHUB_PATH
source "$HOME/Library/Application Support/org.dfinity.dfx/env"
dfx cache install

# check the current ic-commit found in the main branch, check if it differs from the one in this PR branch
# if so, update the  dfx cache with the latest ic artifacts
if [ -f "${GITHUB_WORKSPACE}/.ic-commit" ]; then
    stable_sha=$(curl https://raw.githubusercontent.com/dfinity/examples/master/.ic-commit)
    current_sha=$(sed <"$GITHUB_WORKSPACE/.ic-commit" 's/#.*$//' | sed '/^$/d')
    arch="x86_64-darwin"
    if [ "$current_sha" != "$stable_sha" ]; then
      export current_sha
      export arch
      sh "$GITHUB_WORKSPACE/.github/workflows/update-dfx-cache.sh"
    fi
fi

# Install rust
curl --location --output install-rustup.sh "https://sh.rustup.rs"
bash install-rustup.sh -y
rustup target add wasm32-unknown-unknown

# Exit temporary directory.
popd
