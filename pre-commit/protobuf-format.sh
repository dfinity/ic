#!/usr/bin/env bash

set -euxo pipefail

BUF="$(readlink "$buf_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"
cd "$REPO_PATH"

"$BUF" format -w
