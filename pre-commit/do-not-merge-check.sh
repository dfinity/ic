#!/usr/bin/env bash

set -ueo pipefail

cd "${BUILD_WORKSPACE_DIRECTORY:?Expected to run from bazel}"

ret="0"
git grep -I -i -n -E "DO[^\w]?NOT[^\w]?MERGE" . ":(exclude)pre-commit/BUILD.bazel" ":(exclude)pre-commit/do-not-merge-check.sh" ":(exclude).github/workflows/ci-pr-only.yml" || ret="$?"

case "$ret" in
    0)
        echo "[-] Cannot merge - DO NOT MERGE present in this MR" >&2
        exit 1
        ;;
    1)
        exit 0
        ;;
    *)
        echo "The command exited with the code $ret" >&2
        exit "$ret"
        ;;
esac
