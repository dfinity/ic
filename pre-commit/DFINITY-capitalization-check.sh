#!/usr/bin/env bash

set -ueo pipefail

cd "${BUILD_WORKSPACE_DIRECTORY:?Expected to run from bazel}"

ret="0"
git grep -I -n -E '\bDfinity\b' . ":(exclude)pre-commit/DFINITY-capitalization-check.sh" || ret="$?"

case "$ret" in
    0)
        echo "[-] Improper capitalisation of DFINITY" >&2
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
