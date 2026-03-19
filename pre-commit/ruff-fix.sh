#!/usr/bin/env bash

set -euo pipefail

RUFF="$(realpath "$RUFF")"
cd "${BUILD_WORKSPACE_DIRECTORY:?Expected to run from bazel}"

"$RUFF" check . --fix
"$RUFF" format .
