#!/usr/bin/env bash

set -euo pipefail

CMD="${BAZEL_DEFS_BENCH_PREFIX}${BAZEL_DEFS_BENCH_BIN} --bench $@"

echo "running ${CMD}"
${CMD}
