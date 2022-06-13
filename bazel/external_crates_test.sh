#!/usr/bin/env bash

set -euo pipefail

for f in "$@"; do
    if (grep --fixed-strings --quiet 'wabt' "$f"); then
        echo 'wabt is banned from bazel/external_crates.bzl - build rules should use "@wabt_rs//:wabt"' >&2
        exit 1
    fi
done
