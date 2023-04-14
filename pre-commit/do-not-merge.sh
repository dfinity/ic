#!/usr/bin/env bash

set -ueo pipefail

REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

set +e
git grep -I -i -n -E "DO[^\w]?NOT[^\w]?MERGE" . ":(exclude)pre-commit/BUILD.bazel" ":(exclude)pre-commit/do-not-merge.sh"
E="$?"
set -e

case "$E" in
    0)
        echo "[-] Cannot merge - DO NOT MERGE present in this MR" >&2
        exit 1
        ;;
    1)
        exit 0
        ;;
    *)
        echo "The command exited with the code $E" >&2
        exit "$E"
        ;;
esac
