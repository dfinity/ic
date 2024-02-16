#!/usr/bin/env bash

# This script should only be executed from the gitlab-ci job context.
# To reproduce a build, invoke the Bazel command directly.
# e.g. follow the buildfarm link -> details -> explicit command line.

set -eufo pipefail

echo "Building as user: $(whoami)"
echo "Bazel version: $(bazel version)"

AWS_CREDS="${HOME}/.aws/credentials"
mkdir -p "$(dirname "${AWS_CREDS}")"
# handle github and gitlab differnetly
if [ -n "${AWS_SHARED_CREDENTIALS_FILE+x}" ]; then
    ln -fs "${AWS_SHARED_CREDENTIALS_FILE}" "${AWS_CREDS}"
elif [ -n "${AWS_SHARED_CREDENTIALS_CONTENT+x}" ]; then
    echo "$AWS_SHARED_CREDENTIALS_CONTENT" >"$AWS_CREDS"
else
    echo '$AWS_SHARED_CREDENTIALS_CONTENT or $AWS_SHARED_CREDENTIALS_FILE has to be set' >&2
    exit 1
fi

GITLAB_TOKEN="${HOME}/.gitlab/api_token"
mkdir -p "$(dirname "${GITLAB_TOKEN}")"
echo "${GITLAB_API_TOKEN:-}" >"${GITLAB_TOKEN}"

ic_version_rc_only="0000000000000000000000000000000000000000"
if [ "$CI_COMMIT_REF_PROTECTED" = "true" ]; then
    ic_version_rc_only="${CI_COMMIT_SHA}"
fi

if [[ "${CI_COMMIT_BRANCH:-}" =~ ^hotfix-.+-rc--.+ ]]; then
    ic_version_rc_only="${CI_COMMIT_SHA}"
fi

if [[ "${CI_COMMIT_TAG:-}" =~ ^release-.+ ]]; then
    # upload artifacts also to cloudflare r2
    RC="True"
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
    --rc="${RC:-"False"}" \
    ${BAZEL_EXTRA_ARGS:-} \
    ${BAZEL_TARGETS} \
    2>&1 \
    | perl -pe 'BEGIN { select(STDOUT); $| = 1 } s/(.*Streaming build results to:.*)/\o{33}[92m$1\o{33}[0m/'
