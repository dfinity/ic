#!/usr/bin/env bash

set -eExuo pipefail

if [[ -n "$(git rev-parse -q --verify MERGE_HEAD)" ]]; then
    echo "Currently merging, skipping check-unused-components checks"
    exit 0
fi


bazel run //rs/ic_os/manifest_tool -- --repo-root $(git rev-parse --show-toplevel) check-unused-components
