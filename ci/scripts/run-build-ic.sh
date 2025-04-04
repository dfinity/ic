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
TARGETS=$(ci/bazel-scripts/diff.sh)
if [ "$TARGETS" == "//..." ]; then
    ci/container/build-ic.sh -i -c -b --no-release
    exit 0
fi

ARGS=()

if [[ $TARGETS =~ ic-os ]]; then
    ARGS+=(-i)
fi
if [[ $TARGETS =~ publish/canisters ]]; then
    ARGS+=(-c)
fi
if [[ $TARGETS =~ publish/binaries ]]; then
    ARGS+=(-b)
fi

if [[ ${#ARGS[@]} -eq 0 ]]; then
    echo "No changes that require building IC-OS, binaries or canisters."
    exit 0
fi

ci/container/build-ic.sh "${ARGS[@]}" --no-release
