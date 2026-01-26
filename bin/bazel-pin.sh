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
  $0 [--force]

Options:
  --force       will repin even if repin is not deemed necessary
EOF
}

function help() {
    cat <<EOF
    All packages:
        $0                    # cargo update --workspace

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
            echo "ERROR: no arguments expected, rerun the command without arguments to repin all crates." && echo
            usage && echo
            echo "Use '$0 --help' for more information."
            exit 1
            ;;
    esac
done

if [ $FORCE_REPIN != "1" ] && bazel query @crate_index//:all >/dev/null; then
    # If this isn't a forced repin and if rules_rust still evaluates successfully (using
    # bazel query as a proxy) then we don't need to do anything
    echo "Nothing to repin. Use '$0 --force' to force repin."
    exit 0
fi

echo "Repinning all crates"
CARGO_BAZEL_REPIN=true bazel build @crate_index//...
