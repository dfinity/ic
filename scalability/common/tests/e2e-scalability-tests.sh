#!/usr/bin/env bash

PATH=$PATH:/usr/sbin

if [ -f "${VERSION_FILE_PATH:-}" ]; then
    STATUSFILE="$(cat "${VERSION_FILE_PATH}")"
fi

if [ -f "${STATUSFILE:-}" ]; then
    while read -r k v; do
        case "$k" in
            CI_JOB_ID | CI_RUNNER_TAGS)
                declare "$k=$v"
                export "${k?}"
                ;;
        esac
    done <"$STATUSFILE"
fi

exec "${E2E_TEST_BIN}" \
    --ic_os_version "$(cat "${IC_OS_VERSION_FILE}")" \
    --image_url "$(cat "${IC_OS_IMAGE_URL}")" \
    --image_sha256sum "$(cat "${IC_OS_IMAGE_SHA256SUM}")" \
    --artifacts_path "scalability/artifacts/release/" \
    --nns_canisters "scalability/artifacts/canisters/" \
    --install_nns_bin "scalability/artifacts/release/ic-nns-init" \
    --ic_prep_bin "scalability/artifacts/release/ic-prep"
