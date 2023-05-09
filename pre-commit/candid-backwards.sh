#!/usr/bin/env bash

set -euxo pipefail

SCRIPT="$(readlink "$script_path")"
CANDID_PATH="$(dirname $(readlink $candid_path))"

REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

export PATH="$CANDID_PATH:$PATH"

didc --version

find . -name "*.did" -type f ! -path "./rs/nns/empty.did" -exec "$SCRIPT" {} \+
