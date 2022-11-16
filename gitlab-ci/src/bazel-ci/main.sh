#!/usr/bin/env bash

# This script should only be executed from the gitlab-ci job context.
# To reproduce a build, invoke the Bazel command directly.
# e.g. follow the buildfarm link -> details -> explicit command line.

set -eufo pipefail

bazel version
AWS_CREDS="${HOME}/.aws/credentials"
mkdir -p "$(dirname "${AWS_CREDS}")"
ln -fs "${AWS_SHARED_CREDENTIALS_FILE}" "${AWS_CREDS}"
ln -fs "${DEV_ROOT_CA}" ic-os/guestos/dev-root-ca.crt # https://gitlab.com/dfinity-lab/public/ic/-/blob/master/ic-os/defs.bzl#L85

upload_target_args=""
if [ -n "${BAZEL_UPLOAD_TARGETS:-}" ]; then
    upload_target_args=$(bazel query "kind(upload_artifacts, $BAZEL_UPLOAD_TARGETS)")
fi

ic_version_rc_only="redacted"
if [ "$CI_COMMIT_REF_PROTECTED" = "true" ]; then
    ic_version_rc_only="${CI_COMMIT_SHA}"
fi

# shellcheck disable=SC2086
# ${BAZEL_...} variables are expected to contain several arguments. We have `set -f` set above to disable globbing (and therefore only allow splitting)"
buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" "${CI_JOB_NAME}-bazel-cmd" -- bazel \
    ${BAZEL_STARTUP_ARGS} \
    ${BAZEL_COMMAND} \
    --config ci \
    --build_metadata=BUILDBUDDY_LINKS="[GitLab CI Job](${CI_JOB_URL})" \
    --ic_version="${CI_COMMIT_SHA}" \
    --ic_version_rc_only="${ic_version_rc_only}" \
    ${BAZEL_EXTRA_ARGS} \
    ${BAZEL_TARGETS} \
    ${upload_target_args} \
    2>&1 \
    | perl -pe 'BEGIN { select(STDOUT); $| = 1 } s/(.*Streaming build results to:.*)/\o{33}[92m$1\o{33}[0m/'
