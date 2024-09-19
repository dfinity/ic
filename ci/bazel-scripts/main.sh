#!/usr/bin/env bash

# This script should only be executed from the ci job context.
# To reproduce a build, invoke the Bazel command directly.
# e.g. follow the buildfarm link -> details -> explicit command line.

set -eufo pipefail

# default behavior is to build targets specified in BAZEL_TARGETS and not upload to s3
ic_version_rc_only="0000000000000000000000000000000000000000"
s3_upload="False"

protected_branches=("master" "rc--*" "hotfix-*" "master-private")

# if we are on a protected branch or targeting a rc branch we set ic_version to the commit_sha and upload to s3
for pattern in "${protected_branches[@]}"; do
    if [[ "$BRANCH_NAME" == $pattern ]]; then
        IS_PROTECTED_BRANCH="true"
        break
    fi
done

# if we are on a protected branch or targeting a rc branch we set ic_version to the commit_sha and upload to s3
if [[ "${IS_PROTECTED_BRANCH:-}" == "true" ]] || [[ "${CI_PULL_REQUEST_TARGET_BRANCH_NAME:-}" == "rc--"* ]]; then
    ic_version_rc_only="${CI_COMMIT_SHA}"
    s3_upload="True"
    RUN_ON_DIFF_ONLY="false"
fi

# check if the workflow was triggered by a pull request and if the job requested running only on diff
if [[ "${CI_PIPELINE_SOURCE:-}" == "pull_request" ]]; then
    # if RUN_ALL_BAZEL_TARGETS was requested we upload to s3 and skip the diff check
    if [[ "${CI_PULL_REQUEST_TITLE:-}" == *"[RUN_ALL_BAZEL_TARGETS]"* ]]; then
        s3_upload="True"
    elif [[ "${RUN_ON_DIFF_ONLY:-}" == "true" ]]; then
        # get bazel targets that changed within the MR
        BAZEL_TARGETS=$("${CI_PROJECT_DIR:-}"/ci/bazel-scripts/diff.sh)
    fi
fi

# pass info about bazel targets to bazel-targets file
echo "$BAZEL_TARGETS" >bazel-targets

# if bazel targets is empty we don't need to run any tests
if [ -z "${BAZEL_TARGETS:-}" ]; then
    echo "No bazel targets to build"
    exit 0
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

# An awk (mawk) program used to process STDERR to make it easier
# to find the build event URL when going through logs.
stderr_awk_program='
  # When seeing the stream info line, grab the url and save it as stream_url
  match($0, /Streaming build results to/) \
    { stream_info_line = $0; \
      match(stream_info_line, /https:\/\/[a-zA-Z0-9\/-.]*/); \
      stream_url = substr(stream_info_line, RSTART, RLENGTH) } \
  # In general, forward everyline to the output
  // { print } \
  # Every N lines, repeat the stream info line
  // { if ( stream_info_line != null && NR % 20 == 0 ) print stream_info_line }
  # Finally, print a GitHub notice
  END { print "::notice title=Build Events for "job_name"::"stream_url }'

# shellcheck disable=SC2086
# ${BAZEL_...} variables are expected to contain several arguments. We have `set -f` set above to disable globbing (and therefore only allow splitting)"
buildevents cmd "${ROOT_PIPELINE_ID}" "${CI_JOB_ID}" "${CI_JOB_NAME}-bazel-cmd" -- bazel \
    ${BAZEL_STARTUP_ARGS} \
    ${BAZEL_COMMAND} \
    --color=yes \
    ${BAZEL_CI_CONFIG} \
    --build_metadata=BUILDBUDDY_LINKS="[CI Job](${CI_JOB_URL})" \
    --ic_version="${CI_COMMIT_SHA}" \
    --ic_version_rc_only="${ic_version_rc_only}" \
    --s3_upload="${s3_upload:-"False"}" \
    ${BAZEL_EXTRA_ARGS:-} \
    ${BAZEL_TARGETS} \
    2> >(awk >&2 -v job_name="$CI_JOB_NAME" "$stderr_awk_program")
