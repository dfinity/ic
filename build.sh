#!/bin/bash
set -euxo pipefail

bazel build //rs/canister_sandbox //rs/canister_sandbox:compiler_sandbox //rs/canister_sandbox:sandbox_launcher //rs/execution_environment:large_memory_demo
cp "$(bazel info bazel-bin)/rs/canister_sandbox/compiler_sandbox" .
cp "$(bazel info bazel-bin)/rs/canister_sandbox/sandbox_launcher" .
cp "$(bazel info bazel-bin)/rs/canister_sandbox/canister_sandbox" .
cp "$(bazel info bazel-bin)/rs/execution_environment/large_memory_demo" .