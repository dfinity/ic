#!/usr/bin/env bash

set -euo pipefail

# Verify calls to TVL canister.

echo "Querying get_tvl"
dfx canister call tvl get_tvl "()"

echo "Querying get_tvl_timeseries"
dfx canister call tvl get_tvl_timeseries "()"
