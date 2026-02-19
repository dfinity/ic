#!/bin/bash

set -ex

# Enter temporary directory.
pushd /tmp

# Install Node.
sudo apt-get install nodejs

# Install DFINITY SDK.
wget --output-document install-dfx.sh "https://raw.githubusercontent.com/dfinity/sdk/master/public/install-dfxvm.sh"
DFX_VERSION=${DFX_VERSION:=0.26.1} DFXVM_INIT_YES=true bash install-dfx.sh
rm install-dfx.sh
echo "$HOME/.local/share/dfx/bin" >>$GITHUB_PATH
source "$HOME/.local/share/dfx/env"
dfx cache install
# check the current ic-commit found in the main branch, check if it differs from the one in this PR branch
# if so, update the  dfx cache with the latest ic artifacts
if [ -f "${GITHUB_WORKSPACE}/.ic-commit" ]; then
  stable_sha=$(curl https://raw.githubusercontent.com/dfinity/examples/master/.ic-commit)
  current_sha=$(sed <"$GITHUB_WORKSPACE/.ic-commit" 's/#.*$//' | sed '/^$/d')
  arch="x86_64-linux"
  if [ "$current_sha" != "$stable_sha" ]; then
    export current_sha
    export arch
    sh "$GITHUB_WORKSPACE/.github/workflows/update-dfx-cache.sh"
  fi
fi

# Install rust
wget --output-document install-rustup.sh "https://sh.rustup.rs"
sudo bash install-rustup.sh -y
rustup target add wasm32-unknown-unknown

# Set environment variables.
echo "$HOME/bin" >>$GITHUB_PATH
echo "$HOME/.cargo/bin" >>$GITHUB_PATH

# Exit temporary directory.
popd
