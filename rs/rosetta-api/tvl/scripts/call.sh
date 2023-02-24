#!/usr/bin/env bash

set -euo pipefail

# Verify calls to TVL canister.

echo "Querying get_tvl (update)"
time dfx canister call --update tvl get_tvl "()"

echo "Querying get_tvl (query)"
time dfx canister call --query tvl get_tvl "()"

echo "Querying get_tvl_timeseries (update)"
time dfx canister call tvl get_tvl_timeseries "()"
