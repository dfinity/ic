#!/usr/bin/env bash
# We use subshells to isolate code.  Shellcheck is concerned that changes are meant to be global.
# shellcheck disable=SC2030,SC2031,SC2154
# We use sed a lot, but shellcheck is worried about '$' not expanding to a variable.
# shellcheck disable=SC2016
# We use client-side variable expansion
# shellcheck disable=SC2029,SC2087
# We want arrays to expand into multiple arguments
# shellcheck disable=SC2068

: End shellcheck global rules

: <<'DOC'
tag::catalog[]

Title:: Deploy production NNS state to a testnet

Runbook::
1. Deploy the NNS production state to a testnet.

Success::
- The NNS on the testnet is running the production state.

end::catalog[]

DOC

set -euo pipefail

function exit_usage() {
    echo >&2 "Usage: $0 <testnet> <results_dir>"
    echo >&2 "$0 small01 ./results/"
    exit 1
}

if (($# != 2)); then
    exit_usage
fi

testnet="$1"
results_dir="$(
    mkdir -p "$2"
    realpath "$2"
)"

PEM_FILE="$results_dir/file.pem"
LOG_FILE="$results_dir/file.log"

cat <<EOT >"$PEM_FILE"
-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIKohpVANxO4xElQYXElAOXZHwJSVHERLE8feXSfoKwxX
oSMDIQBqgs2z86b+S5X9HvsxtE46UZwfDHtebwmSQWSIcKr2ew==
-----END PRIVATE KEY-----
EOT

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
cd "$SCRIPT_DIR/../../tools/"

./nns_state_deployment.sh "$testnet" "$GIT_REVISION" "bc7vk-kulc6-vswcu-ysxhv-lsrxo-vkszu-zxku3-xhzmh-iac7m-lwewm-2ae" "$PEM_FILE" &>"$LOG_FILE"

if grep -q "can successfully create proposals" "$LOG_FILE"; then
    echo "SUCCESS!"
else
    echo "FAILURE! Check logs at $LOG_FILE"
fi
