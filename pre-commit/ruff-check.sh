#!/usr/bin/env bash

set -euo pipefail

RUFF="$(realpath "$RUFF")"
cd "${BUILD_WORKSPACE_DIRECTORY:?Expected to run from bazel}"

if ! "$RUFF" check . || ! "$RUFF" format . --check; then
    cat >&2 <<EOF

[-] Linting Python files failed
    Please run the following command to fix it:
    $ bazel run //:ruff-format
EOF
    exit 1
fi
