#!/usr/bin/env bash

# This script is run by the update-mainnet-artifacts job in the ci-pr-only workflow
# to update ./mainnet-artifacts.bzl bazed on the contents of testnet/mainnet_revisions.json.
# The latter tracks the IC version (git revision) of the mainnet NNS subnet (with principal tdb26-...).
#
# This script will set the MAINNET_NNS_SUBNET_IC_VERSION bazel variable and will compute the SHA256 hashes
# of the PUBLISHED_BINARIES which are using the MAINNET_NNS_SUBNET_IC_VERSION.

set -eufo pipefail

EXIT_STATUS=0

# Retrieve the IC version (git revision) of the mainnet NNS subnet:
MAINNET_NNS_SUBNET_IC_VERSION="$(jq '.subnets."tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"' -r testnet/mainnet_revisions.json)"

# Write this IC version to mainnet-artifacts.bzl to give bazel access to it:
sed -i "s/MAINNET_NNS_SUBNET_IC_VERSION = \".*\"/MAINNET_NNS_SUBNET_IC_VERSION = \"$MAINNET_NNS_SUBNET_IC_VERSION\"/" mainnet-artifacts.bzl

# Download the SHA256SUMS file for the binaries of the IC version:
binaries_SHA256SUMS="$(mktemp -t binaries_SHA256SUMS.XXXX)"
trap "rm -f $binaries_SHA256SUMS" EXIT
curl "https://download.dfinity.systems/ic/$MAINNET_NNS_SUBNET_IC_VERSION/binaries/x86_64-linux/SHA256SUMS" \
    --silent --fail -o "$binaries_SHA256SUMS"

# Construct a sed script that subsitutes the old SHA256 hashes with the new SHA256 hashes
# found in the previously downloaded SHA256SUMS file:
sed_script=""
while IFS= read -r line; do
    binary_name="$(echo "$line" | cut -d: -f1 | tr -d '"' | xargs)"
    existing_sha256="$(echo "$line" | cut -d: -f4 | tr -d '"},' | xargs)"
    sha256="$(grep "$binary_name" "$binaries_SHA256SUMS" | cut -d' ' -f1)"
    sed_script+="s/$existing_sha256/$sha256/;"
done <<<$(grep '"rev": MAINNET_NNS_SUBNET_IC_VERSION' mainnet-artifacts.bzl | grep -v '#')

# Apply this sed script to the PUBLISHED_BINARIES dictionary in mainnet-artifacts.bzl
# such that bazel will use the new binaries of IC version:
sed -i "$sed_script" mainnet-artifacts.bzl

# Stage files and check if anything changed
git add mainnet-artifacts.bzl
git status
if ! git diff --cached --quiet; then
    # If this is running from a pull request then update the mainnet-artifacts.bzl file in the PR
    # automatically.
    if [ "$CI_PIPELINE_SOURCE" = "pull_request" ]; then
        # There are some changes staged
        git config --global user.email "infra+github-automation@dfinity.org"
        git config --global user.name "IDX GitHub Automation"
        git commit -m "ci/scripts/update-mainnet-artifacts.sh automatically updated mainnet-artifacts.bzl based on testnet/mainnet_revisions.json"
        git push
    fi

    # Because mainnet-artifacts.bzl needs updating, fail the PR
    EXIT_STATUS=1
fi

exit "${EXIT_STATUS}"
