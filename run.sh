#!/bin/bash
set -euxo pipefail

export COMPILER_BINARY="compiler_sandbox"
export LAUNCHER_BINARY="sandbox_launcher"
export SANDBOX_BINARY="canister_sandbox"

./large_memory_demo
