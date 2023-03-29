#!/usr/bin/env bash

PATH=$PATH:/usr/sbin

STATUSFILE="${CI_PROJECT_DIR:-}/bazel-out/volatile-status.txt"

if [ -f "${STATUSFILE}" ]; then
    while read -r k v; do
        case "$k" in
            CI_JOB_ID | CI_RUNNER_TAGS)
                declare "$k=$v"
                export "${k?}"
                ;;
        esac
    done <"$STATUSFILE"
fi

exec $1 --ic_os_version $(cat $2) \
    --artifacts_path "scalability/artifacts/release/" \
    --nns_canisters "scalability/artifacts/canisters/" \
    --install_nns_bin "scalability/artifacts/release/ic-nns-init" \
    --ic_prep_bin "scalability/artifacts/release/ic-prep"
