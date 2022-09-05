#!/usr/bin/env bash

set -euo pipefail

echo "running ${BAZEL_DEFS_BENCH_BIN}"
"${BAZEL_DEFS_BENCH_BIN}" --bench "$@"
