#!/usr/bin/env bash

set -euo pipefail

RUFF_PATH="$(readlink "$ruff_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

if ! "$RUFF_PATH" check . -q || ! "$RUFF_PATH" format . --check -q; then
    cat >&2 <<EOF

[-] Linting Python files failed
    Please run the following command to fix it:
    $ bazel run //:ruff-format
EOF
    exit 1
fi
