#!/usr/bin/env bash
set -euo pipefail

cd "$CI_PROJECT_DIR"

# run full release build on "protected" branches
if [[ $RELEASE_BUILD == "true" ]]; then
    ci/container/build-ic.sh -i -c -b
    exit 0
fi

# run full non-release build if not asked to diff
if ! [ "${RUN_ON_DIFF_ONLY:-}" == "true" ]; then
    ci/container/build-ic.sh -i -c -b --no-release
    exit 0
fi

# otherwise, infer targets to build
targets=$(mktemp)
ci/bazel-scripts/diff.sh build "${MERGE_BASE_SHA:-HEAD}..${BRANCH_HEAD_SHA:-}" >"$targets"

ARGS=()

if grep -q '^//ic-os' <"$targets"; then
    ARGS+=(-i)
fi
if grep -q '^//publish/canisters' <"$targets"; then
    ARGS+=(-c)
fi
if grep -q '^//publish/binaries' <"$targets"; then
    ARGS+=(-b)
fi

rm "$targets"

if [[ ${#ARGS[@]} -eq 0 ]]; then
    echo "No changes that require building IC-OS, binaries or canisters."
    exit 0
fi

if [ ! -e /cache ]; then
    sudo mkdir -p /cache/bazel/content_addressable && sudo chown -R 1001:1001 /cache
fi

ci/container/build-ic.sh "${ARGS[@]}" --no-release
