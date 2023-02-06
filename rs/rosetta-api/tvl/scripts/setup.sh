#!/usr/bin/env bash

set -euo pipefail

# Before running this benchmark, first start DFX (version 12.1) with:
# $ dfx start --log tee --logfile tvl-log-$(date +"%Y-%m-%d").txt --clean

# Set the principal running the experiment.
# PRINCIPAL=$(dfx identity get-principal)

NETWORK=local

echo "Installing NNS canisters"

# Use custom governance canister (with get_metrics endpoint) since it's not released yet.
#bazel build //rs/nns/governance:governance-canister
#cp bazel-bin/rs/nns/governance/governance-canister.wasm ~/.cache/dfinity/versions/0.12.1/wasms/governance-canister_test.wasm
cp ../governance/governance-canister.wasm ~/.cache/dfinity/versions/0.12.1/wasms/governance-canister_test.wasm

dfx nns install
#dfx nns import

# Sample manual test usage:
# dfx canister call --candid ../../../nns/governance/canister/governance.did nns-governance get_metrics '()'

# Continue with TVL deployment.
./deploy-tvl.sh
