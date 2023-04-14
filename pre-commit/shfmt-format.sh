#!/usr/bin/env bash

set -euxo pipefail

SHFMT="$(readlink "$shfmt_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

find . -type f -name "*.sh" -exec "$SHFMT" -w -i 4 -bn -ci {} \+
