#!/usr/bin/env bash

# This script should only be executed from the ci job context.
# To reproduce a build, invoke the Bazel command directly.
# e.g. follow the buildfarm link -> details -> explicit command line.

set -eufo pipefail

# default behavior is to build targets specified in BAZEL_TARGETS and not upload to s3
release_build="false"

# List of "protected" branches, i.e. branches (not necessarily "protected" in the GitHub sense) where we need
# the full build to occur (including versioning
protected_branches=("^master$" "^rc--" "^hotfix-" "^master-private$")
for pattern in "${protected_branches[@]}"; do
    if [[ "$BRANCH_NAME" =~ $pattern ]]; then
        IS_PROTECTED_BRANCH="true"
        break
    fi
done

# if we are on a "protected" branch or targeting a rc branch we upload all artifacts and run a release build
# (with versioning)
if [[ "${IS_PROTECTED_BRANCH:-}" == "true" ]]; then
    release_build="true"
    RUN_ON_DIFF_ONLY="false"
fi

if [[ "${CI_EVENT_NAME:-}" == "merge_group" ]]; then
    RUN_ON_DIFF_ONLY="false"
fi

if [[ "${RUN_ON_DIFF_ONLY:-}" == "true" ]]; then
    # get bazel targets that changed within the MR
    BAZEL_TARGETS=$("${CI_PROJECT_DIR:-}"/ci/bazel-scripts/diff.sh)
fi

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
if [ -n "${CLOUD_CREDENTIALS_CONTENT+x}" ]; then
    echo "$CLOUD_CREDENTIALS_CONTENT" >"$AWS_CREDS"
    unset CLOUD_CREDENTIALS_CONTENT
fi

if [ -z "${KUBECONFIG:-}" ] && [ -n "${KUBECONFIG_TNET_CREATOR_LN1:-}" ]; then
    KUBECONFIG=$(mktemp -t kubeconfig-XXXXXX)
    export KUBECONFIG
    echo "$KUBECONFIG_TNET_CREATOR_LN1" >"$KUBECONFIG"
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

bazel_args=(
    --output_base=/var/tmp/bazel-output # Output base wiped after run
    ${BAZEL_COMMAND}
    ${BAZEL_TARGETS}
    --color=yes
    --build_metadata=BUILDBUDDY_LINKS="[CI Job](${CI_JOB_URL})"
)

if [[ $release_build == true ]]; then
    bazel_args+=(--config=release)
fi

# Unless explicitly provided, we set a default --repository_cache to a volume mounted inside our runners
# Only for Linux builds since there `/cache` is mounted to host local storage.
if [[ ! " ${bazel_args[*]} " =~ [[:space:]]--repository_cache[[:space:]] ]] && [[ "$(uname)" == "Linux" ]]; then
    echo "setting default repository cache"
    bazel_args+=(--repository_cache=/cache/bazel)
fi

bazel "${bazel_args[@]}" 2>&1 | awk -v url_out="$url_out" "$stream_awk_program"

# Write the bes link & summary
echo "Build results uploaded to $(<"$url_out")"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    invocation=$(sed <"$url_out" 's;.*/;;') # grab invocation ID (last url part)
    echo "BuildBuddy [$invocation]($(<"$url_out"))" >>"$GITHUB_STEP_SUMMARY"
fi
rm "$url_out"

# List and aggregate all SHA256SUMS files.
if [ -e ./bazel-out/ ]; then
    for shafile in $(find bazel-out/ -name SHA256SUMS); do
        if [ -f "$shafile" ]; then
            echo "$shafile"
        fi
    done | xargs cat | sort | uniq >SHA256SUMS
else
    # if no bazel-out, assume no targets were built
    touch SHA256SUMS
fi
