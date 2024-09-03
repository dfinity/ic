#!/usr/bin/env bash

# This script should only be executed from the gitlab-ci job context.
# To reproduce a build, invoke the Bazel command directly.
# e.g. follow the buildfarm link -> details -> explicit command line.

set -eufo pipefail

ic_version_rc_only="0000000000000000000000000000000000000000"
# if we are on a protected branch or the PR is targeting an rc branch or building all targets was requested, we run all bazel targets and upload to S3
if [[ "$CI_COMMIT_REF_PROTECTED" = "true" ]] || [[ "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" == "rc--"* ]] \ 
    || [[ "${CI_MERGE_REQUEST_TITLE:-}" == *"[RUN_ALL_BAZEL_TARGETS]"* ]]; then
    ic_version_rc_only="${CI_COMMIT_SHA}"
    RUN_ON_DIFF_ONLY="false"
    s3_upload="True"
fi

# if on a pull_request, only run build on targets that have changed
if [ "${RUN_ON_DIFF_ONLY:-}" == "true" ] && [ "${CI_PIPELINE_SOURCE:-}" == "pull_request" ]; then
    # get bazel targets that changed within the MR
    BAZEL_TARGETS=$("${CI_PROJECT_DIR:-}"/ci/bazel-scripts/diff.sh)

    # pass info about bazel targets to bazel-targets file
    echo "$BAZEL_TARGETS" >bazel-targets

    # if bazel targets is empty we don't need to run any tests
    if [ -z "${BAZEL_TARGETS:-}" ]; then
        echo "No bazel targets to build"
        exit 0
    fi
fi

echo "Building as user: $(whoami)"
echo "Bazel version: $(bazel version)"

AWS_CREDS="${HOME}/.aws/credentials"
mkdir -p "$(dirname "${AWS_CREDS}")"

# add aws credentials file if it's set
if [ -n "${AWS_SHARED_CREDENTIALS_CONTENT+x}" ]; then
    echo "$AWS_SHARED_CREDENTIALS_CONTENT" >"$AWS_CREDS"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "upload_artifacts=true" >>"$GITHUB_OUTPUT"
fi

if [ -z "${KUBECONFIG:-}" ] && [ ! -z "${KUBECONFIG_TNET_CREATOR_LN1:-}" ]; then
    export KUBECONFIG=$(mktemp -t kubeconfig-XXXXXX)
    echo $KUBECONFIG_TNET_CREATOR_LN1 >$KUBECONFIG
    trap 'rm -f -- "$KUBECONFIG"' EXIT
fi

# shellcheck disable=SC2086
# ${BAZEL_...} variables are expected to contain several arguments. We have `set -f` set above to disable globbing (and therefore only allow splitting)"
buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" "${CI_JOB_NAME}-bazel-cmd" -- bazel \
    ${BAZEL_STARTUP_ARGS} \
    ${BAZEL_COMMAND} \
    ${BAZEL_CI_CONFIG} \
    --build_metadata=BUILDBUDDY_LINKS="[CI Job](${CI_JOB_URL})" \
    --ic_version="${CI_COMMIT_SHA}" \
    --ic_version_rc_only="${ic_version_rc_only}" \
    --s3_upload="${s3_upload:-"False"}" \
    ${BAZEL_EXTRA_ARGS:-} \
    ${BAZEL_TARGETS} \
    2>&1 \
    | perl -pe 'BEGIN { select(STDOUT); $| = 1 } s/(.*Streaming build results to:.*)/\o{33}[92m$1\o{33}[0m/'
