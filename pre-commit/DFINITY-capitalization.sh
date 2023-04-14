#!/usr/bin/env bash

set -ueo pipefail

REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

set +e
git grep -I -n -E '\bDfinity\b' . ":(exclude)pre-commit/DFINITY-capitalization.sh"
E="$?"
set -e

case "$E" in
    0)
        echo "[-] Improper capitalisation of DFINITY" >&2
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
