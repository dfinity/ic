#!/usr/bin/env bash

# This script should only be executed from the gitlab-ci job context.
# To reproduce a build, invoke the Bazel command directly.
# e.g. follow the buildfarm link -> details -> explicit command line.

set -eufo pipefail

echo "Building as user: $(whoami)"
echo "Bazel version: $(bazel version)"

AWS_CREDS="${HOME}/.aws/credentials"
mkdir -p "$(dirname "${AWS_CREDS}")"
ln -fs "${AWS_SHARED_CREDENTIALS_FILE}" "${AWS_CREDS}"

ic_version_rc_only="0000000000000000000000000000000000000000"
if [ "$CI_COMMIT_REF_PROTECTED" = "true" ]; then
    ic_version_rc_only="${CI_COMMIT_SHA}"
fi

# Many actions seem to be using much more resources than bazel expects.
# Running too many of them in parallel causes some tests that expect to get some resources within limited time to fail.
# TODO(IDX-2225): reconsider limit when we will use Remute Execution.
if [ "$(nproc)" -gt 32 ]; then
    BAZEL_EXTRA_ARGS="--jobs=32 ${BAZEL_EXTRA_ARGS}"
fi

# shellcheck disable=SC2086
# ${BAZEL_...} variables are expected to contain several arguments. We have `set -f` set above to disable globbing (and therefore only allow splitting)"
buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" "${CI_JOB_NAME}-bazel-cmd" -- bazel \
    ${BAZEL_STARTUP_ARGS} \
    ${BAZEL_COMMAND} \
    ${BAZEL_CI_CONFIG} \
    --build_metadata=BUILDBUDDY_LINKS="[GitLab CI Job](${CI_JOB_URL})" \
    --ic_version="${CI_COMMIT_SHA}" \
    --ic_version_rc_only="${ic_version_rc_only}" \
    ${BAZEL_EXTRA_ARGS} \
    ${BAZEL_TARGETS} \
    2>&1 \
    | perl -pe 'BEGIN { select(STDOUT); $| = 1 } s/(.*Streaming build results to:.*)/\o{33}[92m$1\o{33}[0m/'
