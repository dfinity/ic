#!/usr/bin/env bash

set -euo pipefail

BUF="$(realpath "$BUF")"
cd "${BUILD_WORKSPACE_DIRECTORY:?Expected to run from bazel}"

"$BUF" format --exit-code --diff .
"$BUF" lint .
