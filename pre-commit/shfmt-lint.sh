#!/usr/bin/env bash

set -euo pipefail

SHFMT="$(readlink "$shfmt_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

if ! find . -path ./.git -prune -o -type f -name "*.sh" -exec "$SHFMT" -d -w -i 4 -bn -ci {} \+; then
    cat >&2 <<EOF

[-] Linting Bash script failed
    Please run the following command to fix it:
    $ bazel run //:shfmt-format
EOF
    exit 1
fi
