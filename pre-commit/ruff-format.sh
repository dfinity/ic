#!/usr/bin/env bash

set -euxo pipefail

RUFF_PATH="$(readlink "$ruff_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

"$RUFF_PATH" check . --fix
"$RUFF_PATH" format .
