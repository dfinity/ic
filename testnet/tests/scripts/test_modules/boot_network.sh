#!/usr/bin/env bash

# scenario test script module.
# Name: network_boot.sh
# Args: <testnet_identifier> <results_dir>
# Roughly speaking, this script:
# - sets up the testnet (nns + subnet installation)

echo "booting network ..."

if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet_identifier> and <results_dir>"
    echo >&2 "$0 p2p_15"
    exit 1
fi

testnet="$1"
experiment_dir="$2"

forbidden_testnets="mercury"
for item in $forbidden_testnets; do
    if [[ "$testnet" == "$item" ]]; then
        echo >&2 "This script is not intended to run against the '${item}' testnet. Aborting."
        exit 1
    fi
done

if [[ ! -d "$PROD_SRC/env/$testnet" ]]; then
    echo >&2 "'$testnet' doesn't exist (checked at '$PROD_SRC/env/$testnet'), aborting."
    exit 1
fi

echo "Booting testnet with identifier $testnet"

# Preparatory work
if [[ -n "${LEGACY_TESTNET:-}" ]]; then
    testnet-install-head-sh "$testnet" | tee -a "$experiment_dir/ansible.log"
else
    # re-deploy the testnet
    deploy_with_timeout "$testnet" --git-revision "$GIT_REVISION"
fi
