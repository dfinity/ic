#!/usr/bin/env bash

# This script should only be executed from the ci job context.
# To reproduce a build, invoke the Bazel command directly.
# e.g. follow the buildfarm link -> details -> explicit command line.

set -eufo pipefail

# default behavior is to build targets specified in BAZEL_TARGETS and not upload to s3
ic_version_rc_only="0000000000000000000000000000000000000000"
release_build="false"
s3_upload="False"

protected_branches=("master" "rc--*" "hotfix-*" "master-private")

# if we are on a protected branch or targeting a rc branch we set ic_version to the commit_sha and upload to s3
for pattern in "${protected_branches[@]}"; do
    if [[ "$BRANCH_NAME" == $pattern ]]; then
        IS_PROTECTED_BRANCH="true"
        break
    fi
done

# if we are on a protected branch or targeting a rc branch we set release build, ic_version to the commit_sha and
# upload to s3
if [[ "${IS_PROTECTED_BRANCH:-}" == "true" ]] || [[ "${CI_PULL_REQUEST_TARGET_BRANCH_NAME:-}" == "rc--"* ]]; then
    ic_version_rc_only="${CI_COMMIT_SHA}"
    s3_upload="True"
    release_build="true"
    RUN_ON_DIFF_ONLY="false"
fi

if [[ "${CI_EVENT_NAME:-}" == "merge_group" ]]; then
    s3_upload="False"
    RUN_ON_DIFF_ONLY="false"
fi

if [[ "${RUN_ON_DIFF_ONLY:-}" == "true" ]]; then
    # get bazel targets that changed within the MR
    BAZEL_TARGETS=$("${CI_PROJECT_DIR:-}"/ci/bazel-scripts/diff.sh)
else
    s3_upload="True"
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
# Finally we record the URL to 'url_out' (passed via variable)
url_out=$(mktemp)
stream_awk_program='
  # When seeing the stream info line, grab the url and save it as stream_url
  match($0, /Streaming build results to/) \
    { stream_info_line = $0; \
      match(stream_info_line, /https:\/\/[a-zA-Z0-9\/-.]*/); \
      stream_url = substr(stream_info_line, RSTART, RLENGTH); \
  } \
  # In general, forward every line to the output
  // { print } \
  # Every N lines, repeat the stream info line
  // { if ( stream_info_line != null && NR % 20 == 0 ) print stream_info_line } \
  # Finally, record the URL
  END { if (stream_url != null) print stream_url > url_out }'

# shellcheck disable=SC2086
# ${BAZEL_...} variables are expected to contain several arguments. We have `set -f` set above to disable globbing (and therefore only allow splitting)"
buildevents cmd "${CI_RUN_ID}" "${CI_JOB_NAME}" "${CI_JOB_NAME}-bazel-cmd" -- bazel \
    ${BAZEL_STARTUP_ARGS} \
    ${BAZEL_COMMAND} \
    --color=yes \
    ${BAZEL_CI_CONFIG} \
    --build_metadata=BUILDBUDDY_LINKS="[CI Job](${CI_JOB_URL})" \
    --ic_version="${CI_COMMIT_SHA}" \
    --ic_version_rc_only="${ic_version_rc_only}" \
    --release_build="${release_build}" \
    --s3_upload="${s3_upload:-"False"}" \
    ${BAZEL_EXTRA_ARGS:-} \
    ${BAZEL_TARGETS} \
    2>&1 | awk -v url_out="$url_out" "$stream_awk_program"

# Write the bes link & summary
echo "Build results uploaded to $(<"$url_out")"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    invocation=$(sed <"$url_out" 's;.*/;;') # grab invocation ID (last url part)
    echo "BuildBuddy [$invocation]($(<"$url_out"))" >>$GITHUB_STEP_SUMMARY
fi
rm "$url_out"
