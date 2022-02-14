#!/usr/bin/env bash

set +x
set -ue

# Find replica revision of the subnet from mainnet
mainnet_nns="https://ic0.app/"
nns_subnet_id="tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
if [[ $TEST_SUBNET == "app" ]]; then
    # Find oldest app subnet revision
    max_distance=-1
    revision=""
    subnets=$(
        "${IC_ADMIN}" --nns-url "$mainnet_nns" get-subnet-list | jq -r '.[]'
    )
    for sn in $subnets; do
        if [[ $sn == $nns_subnet_id ]]; then
            # Skip NNS subnet when retrieving oldest revision from app subnets
            continue
        fi
        sn_revision=$("${IC_ADMIN}" --nns-url "$mainnet_nns" get-subnet "$sn" | jq '.records[0].value.replica_version_id' | xargs)
        max_depth="-1"
        depth=$(($(git rev-list --count "$sn_revision"..HEAD) - 1))

        if ((depth > max_depth)); then
            max_depth=$depth
            revision=$sn_revision
        fi
    done
    echo "Mainnet subnet $sn has oldest revision $revision with depth of $depth."
else
    # Find oldest NNS subnet revision
    revision=$("${IC_ADMIN}" --nns-url "$mainnet_nns" get-subnet $nns_subnet_id | jq '.records[0].value.replica_version_id' | xargs)
    echo "NNS subnet on mainnet has revision $revision"
fi

set -x
