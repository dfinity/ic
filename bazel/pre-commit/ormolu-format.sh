#!/usr/bin/env bash

set -euo pipefail

ORMOLU="$(readlink "$ormolu_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

find . -type f -name "*.hs" -exec "$ORMOLU" --mode inplace {} \+
