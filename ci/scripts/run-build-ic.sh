#!/usr/bin/env bash

set -euo pipefail
VERSION=$(git rev-parse HEAD)

cd "$CI_PROJECT_DIR"

protected_branches=("master" "rc--*" "hotfix-*" "master-private")

# if we are on a protected branch or targeting a rc branch we set ic_version to the commit_sha and upload to s3
for pattern in "${protected_branches[@]}"; do
    if [[ "$BRANCH_NAME" == $pattern ]]; then
        IS_PROTECTED_BRANCH="true"
        break
    fi
done

# run build with release on protected branches or if a pull_request is targeting an rc branch
if [ "${IS_PROTECTED_BRANCH:-}" == "true" ] || [[ "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" == "rc--"* ]]; then
    ci/container/build-ic.sh -i -c -b
# if an override was requested to run all bazel targets with no release
elif [[ "${CI_PULL_REQUEST_TITLE:-}" == *"[RUN_ALL_BAZEL_TARGETS]"* ]]; then
    ci/container/build-ic.sh -i -c -b --no-release
# check if the workflow was triggered by a pull request and if the job requested running only on diff
elif [[ "${CI_PIPELINE_SOURCE:-}" == "pull_request" ]] && [[ "${RUN_ON_DIFF_ONLY:-}" == "true" ]]; then
    TARGETS=$(ci/bazel-scripts/diff.sh)
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
# otherwise run full build but with no release
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
