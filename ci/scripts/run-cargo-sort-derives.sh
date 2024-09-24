#!/bin/bash

# The crate and version you want to check and reinstall
CRATE_NAME="cargo-sort-derives"
REQUIRED_VERSION="0.6.0"

# Check the installed version of the crate
INSTALLED_VERSION=$(cargo search $CRATE_NAME | grep "^$CRATE_NAME" | grep "$REQUIRED_VERSION" | cut -d'"' -f2)

if [ "$INSTALLED_VERSION" == "$REQUIRED_VERSION" ]; then
    echo "$CRATE_NAME version $REQUIRED_VERSION is already installed."
else
    echo "$CRATE_NAME version $REQUIRED_VERSION is not installed, installing now..."
    cargo install --force $CRATE_NAME --version $REQUIRED_VERSION
fi

# Run the crate with cargo
echo "Running $CRATE_NAME..."
cargo sort-derives
