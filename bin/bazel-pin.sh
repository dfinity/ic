#!/usr/bin/env bash

set -euo pipefail

#########
# USAGE #
#########

function title() {
    echo "Repin Bazel Crates"
}

function usage() {
    cat <<EOF
Usage:
  $0 [--force] [crate ...]

Options:
  --force       will repin even if repin is not deemed necessary
  crate         crate to repin (e.g. serde or serde@1.0.130)
EOF
}

function help() {
    cat <<EOF
    All packages:
        $0                    # cargo update --workspace

    Specific packages:
        $0 serde              # cargo update --package serde
        $0 serde@1.0.130      # cargo update --package serde --precise 1.0.130

    Details: https://bazelbuild.github.io/rules_rust/crate_universe.html#repinning--updating-dependencies
EOF

}

FORCE_REPIN=0
CRATES=()

# ARGUMENT PARSING

while [[ $# -gt 0 ]]; do
    case $1 in
        -h | --help)
            title && echo && usage && echo && help
            exit 0
            ;;
        --force)
            FORCE_REPIN=1
            shift
            ;;
        --*)
            echo "ERROR: unknown argument $1" && echo
            usage && echo
            echo "Use '$0 --help' for more information."
            exit 1
            ;;
        *)
            CRATES+=("$1")
            shift
            ;;
    esac
done

if [ ${#CRATES[@]} -eq 0 ]; then
    if [ $FORCE_REPIN != "1" ] && bazel query @crate_index//:all >/dev/null; then
        # If this isn't a forced repin and if rules_rust still evaluates successfully (using
        # bazel query as a proxy) then we don't need to do anything
        echo "Nothing to repin. Use '$0 --force' to force repin."
        exit 0
    fi
    echo "Repinning all crates"
    CARGO_BAZEL_REPIN=true bazel build @crate_index//...
else
    echo "Repinning crates: ${CRATES[*]}"
    CARGO_BAZEL_REPIN="${CRATES[*]}" bazel build @crate_index//...
fi
