#!/usr/bin/env bash

set -euo pipefail

echo "running ${TESTS_BENCH_BIN}"
eval "${TESTS_BENCH_BIN}"
