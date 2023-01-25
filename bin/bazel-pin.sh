#!/usr/bin/env bash

set -euo pipefail

CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
DFINITY_OPENSSL_STATIC=1 CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
