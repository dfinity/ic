#!/usr/bin/env bash

set -euxo pipefail

BUF="$(readlink "$buf_path")"
CONF="$(readlink "$buf_config")"
REPO_PATH="$(dirname "$(readlink "$MODULE")")"
cd "$REPO_PATH"

"$BUF" lint --config="$CONF" .
