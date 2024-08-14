#!/usr/bin/env bash
set -Eexuo pipefail

# With --sample-size 20 should take ~10 minutes.
bazel run //rs/execution_environment:management_canister_bench -- --sample-size 20
