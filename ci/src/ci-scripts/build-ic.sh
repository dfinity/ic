#!/usr/bin/env bash

set -euo pipefail
VERSION=$(git rev-parse HEAD)

if [[ "${CI_MERGE_REQUEST_TITLE:-}" == *"[RUN_ALL_BAZEL_TARGETS]"* ]] || [[ "${CI_MERGE_REQUEST_TITLE:-}" == *"[S3_UPLOAD]"* ]]; then
    RUN_ON_DIFF_ONLY="false"
fi

cd "$CI_PROJECT_DIR"

if [ "$CI_COMMIT_REF_PROTECTED" == "true" ] \
    || [[ "${CI_COMMIT_BRANCH:-}" =~ ^hotfix-.* ]]; then
    ci/container/build-ic.sh -i -c -b
elif [ "${RUN_ON_DIFF_ONLY:-}" == "true" ] \
    && [ "${CI_PIPELINE_SOURCE:-}" == "merge_request_event" -o "${CI_PIPELINE_SOURCE:-}" == "pull_request" ] \
    && [ "${CI_MERGE_REQUEST_EVENT_TYPE:-}" != "merge_train" ] \
    && [[ "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" != "rc--"* ]]; then

    TARGETS=$(ci/src/bazel-ci/diff.sh)
    ARGS=(--no-release)

    if [ "$TARGETS" == "//..." ]; then
        ARGS+=(-i -c -b)
    else
        if grep -q "ic-os" <<<"$TARGETS"; then
            ARGS+=(-i)
        fi
        if grep -q "publish/canisters" <<<"$TARGETS"; then
            ARGS+=(-c)
        fi
        if grep -q "publish/binaries" <<<"$TARGETS"; then
            ARGS+=(-b)
        fi
    fi

    if [ ${#ARGS[@]} -eq 1 ]; then
        echo "No changes that require building IC-OS, binaries or canisters."
        touch build-ic.tar
        exit 0
    fi
    ci/container/build-ic.sh "${ARGS[@]}"
else
    ci/container/build-ic.sh -i -c -b --no-release
fi

if [ -d artifacts/icos ]; then
    # purge test image
    find ./artifacts/icos -name 'update-img-test.*' -delete
    # only keep zstd ic images
    find ./artifacts/icos -name '*.gz' -delete
fi

tar -chf artifacts.tar artifacts
ls -l /ceph-s3-info/** || true
URL="http://$(cat /ceph-s3-info/BUCKET_HOST)/$(cat /ceph-s3-info/BUCKET_NAME)/${VERSION}/${CI_JOB_ID}"
curl --request PUT --upload-file artifacts.tar "${URL}/artifacts.tar"

mkdir build-ic
for DIR in release canisters icos/guestos icos/hostos icos/setupos; do
    if [ -e "artifacts/${DIR}/SHA256SUMS" ]; then
        mkdir -p "build-ic/${DIR}/"
        cp "artifacts/${DIR}/SHA256SUMS" "build-ic/${DIR}/"
    fi
done

EXTERNAL_URL="https://objects.$(echo "${NODE_NAME:-}" | cut -d'-' -f1)-idx1.dfinity.network/$(cat /ceph-s3-info/BUCKET_NAME)/${VERSION}/${CI_JOB_ID}/artifacts.tar"
echo -e "Node: ${NODE_NAME:-}\nURL: ${URL}\nExternal URL: ${EXTERNAL_URL}" >./build-ic/info
echo "${EXTERNAL_URL}" >./build-ic/url
tar -cf build-ic.tar build-ic
