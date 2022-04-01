#!/usr/bin/env bash

set +x
set -ue

# Find replica revision of the subnet from mainnet
mainnet_nns="https://ic0.app/"
nns_subnet_id="tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe"
# Find oldest NNS subnet revision
export TARGET_VERSION=$("${IC_ADMIN}" --nns-url "$mainnet_nns" get-subnet $nns_subnet_id | jq '.records[0].value.replica_version_id' | xargs)
echo "NNS subnet on mainnet has revision $TARGET_VERSION"

set -x
