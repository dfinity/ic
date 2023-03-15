#!/usr/bin/env bash

set -euo pipefail

REPIN="${1:-1}"

case "${REPIN}" in
    -h | --help)
        cat <<EOF >&2
        usage:
            $0                    # cargo update --workspace
            $0 package_name       # cargo upgrade --package package_name
            $0 package_name@1.2.3 # cargo upgrade --package package_name --precise 1.2.3

        Details: https://bazelbuild.github.io/rules_rust/crate_universe.html#repinning--updating-dependencies
EOF
        exit 0
        ;;
esac

CARGO_BAZEL_REPIN="${REPIN}" bazel sync --only=crate_index
DFINITY_OPENSSL_STATIC=1 CARGO_BAZEL_REPIN="${REPIN}" bazel sync --only=crate_index
