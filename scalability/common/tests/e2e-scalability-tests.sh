#!/usr/bin/env bash

PATH=$PATH:/usr/sbin

exec $1 --ic_os_version $(cat $2) \
    --artifacts_path "scalability/artifacts/release/" \
    --nns_canisters "scalability/artifacts/canisters/" \
    --install_nns_bin "scalability/artifacts/release/ic-nns-init" \
    --ic_prep_bin "scalability/artifacts/release/ic-prep"
