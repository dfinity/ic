#!/usr/bin/env bash

set -euxo pipefail

SHELLCHECK="$(readlink "$shellcheck_path")"
REPO_PATH="$(dirname "$(readlink "$WORKSPACE")")"

cd "$REPO_PATH"

# TODO IDX-2796 - enable for the whole repository
# Run shellcheck for all testnet/tests/scripts/*.sh
find testnet/tests/scripts/ -maxdepth 1 -type f -name "*.sh" -print0 | xargs -0 -P "$(nproc)" "$SHELLCHECK" --source-path=include

# Run shellcheck in for testnet/tests/scripts/test_modules/*.sh
find testnet/tests/scripts/test_modules/ -maxdepth 1 -type f -name "*.sh" -print0 | xargs -0 -P "$(nproc)" "$SHELLCHECK" --source-path=include
