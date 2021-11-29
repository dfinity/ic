#!/usr/bin/env bash

# scenario test script module.
# Name: collect_nodes.sh
# Args: <testnet> <results_dir>
# Roughly speaking, this script:
# - collects the nodes in the target network so that they can be used by other modules
#   the nodes are stored in <results_dir>/node_indices

if (($# != 2)); then
    echo >&2 "Wrong number of arguments, please provide values for <testnet> <results_dir>"
    exit 1
fi

testnet="$1"
results_dir="$2"

# These are the hosts that the workload generator will target.
# We select all of them.
loadhosts=$(
    cd "$PROD_SRC" || exit 1
    ansible-inventory -i "env/$testnet/hosts" --list \
        | jq -L"${PROD_SRC}/jq" -r 'import "ansible" as ansible;
               ._meta.hostvars |
               [
                 with_entries(select(.value.subnet_index==1))[] |
                 ansible::interpolate |
                 .api_listen_url
               ] |
               join(",")'
)
echo "$loadhosts" >"$results_dir/loadhosts"
