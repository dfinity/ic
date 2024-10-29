#!/bin/bash
set -euxo pipefail

export BAZEL_BIN="$(bazel info bazel-bin)"
bazel build //rs/canister_sandbox //rs/canister_sandbox:compiler_sandbox //rs/canister_sandbox:sandbox_launcher
bazel build //rs/execution_environment:large_memory_demo
export COMPILER_BINARY="$BAZEL_BIN/rs/canister_sandbox/compiler_sandbox"
export LAUNCHER_BINARY="$BAZEL_BIN/rs/canister_sandbox/sandbox_launcher"
export SANDBOX_BINARY="$BAZEL_BIN/rs/canister_sandbox/canister_sandbox"

$BAZEL_BIN/rs/execution_environment/large_memory_demo
