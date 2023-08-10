#!/usr/bin/env bash

set -euxo pipefail

BUF="$(readlink "$buf_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

if ! "$BUF" format --exit-code --diff; then
    cat >&2 <<EOF

[-] Linting Protobuf files failed
    Please run the following command to fix it:
    $ bazel run //:protobuf-format
EOF
    exit 1
fi
