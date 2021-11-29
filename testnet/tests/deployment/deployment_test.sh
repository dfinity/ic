#!/usr/bin/env bash
set -eu

if (($# != 1)); then
    echo >&2 "Missing arguments, please provide values for <testnet_identifier>:"
    echo >&2 "$0 cd"
    exit 1
fi

testnet="$1"

testnet-install-head-sh "$testnet"

cd "$PROD_SRC"

loadhosts=$(
    ansible-inventory -i "env/$testnet/hosts" --list \
        | jq -r '._meta.hostvars | 
             with_entries(select(.value.subnet_index==1)) |
             .[keys | first] | . as $dict |
             with_entries({"key": .key, 
               "value": .value | tostring | 
                 until(test("{") | not; gsub("{{(?<v>.+?)}}"; $dict[.v] | tostring))
              }) |
             .api_listen_addr'
)

echo "run IC workload generator against the first node in subnet 0: $loadhosts"
# The workload generator needs many file descriptors.
ic-workload-generator -u -r 100 -n 1 "http://$loadhosts"

echo "Successfully deployed the IC to the $testnet testnet!"
