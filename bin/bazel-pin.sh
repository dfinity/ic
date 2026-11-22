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
  $0 [--force] [--full] [crate ...]

Options:
  --force       will repin even if repin is not deemed necessary
  --full        update every crate to the newest version allowed by its requirement,
                then repin the given crates (if any)
  crate         crate to repin (e.g. serde, serde=1.0.130 or serde@1.0.228=1.0.130)
EOF
}

function help() {
    cat <<EOF
    All packages:
        $0                          # cargo update --workspace
        $0 --full                   # cargo update
        $0 --full serde=1.0.130     # cargo update, then hold serde at 1.0.130

    Specific packages (repinned one after the other, in the given order):
        $0 serde                    # cargo update --package serde
        $0 serde=1.0.130            # cargo update --package serde --precise 1.0.130
        $0 serde@1.0.228=1.0.130    # cargo update --package serde@1.0.228 --precise 1.0.130

    Details: https://github.com/bazelbuild/rules_rust/blob/0.75.0/crate_universe/src/metadata.rs (CargoUpdateRequest)
EOF

}

FORCE_REPIN=0
FULL_REPIN=0
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
        --full)
            FULL_REPIN=1
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

if [ $FULL_REPIN = "1" ]; then
    echo "Repinning all crates to their newest allowed versions"
    CARGO_BAZEL_REPIN=full bazel build @crate_index//...
fi

if [ ${#CRATES[@]} -eq 0 ]; then
    if [ $FULL_REPIN = "1" ]; then
        exit 0
    fi
    if [ $FORCE_REPIN != "1" ] && bazel query @crate_index//:all >/dev/null; then
        # If this isn't a forced repin and if rules_rust still evaluates successfully (using
        # bazel query as a proxy) then we don't need to do anything
        echo "Nothing to repin. Use '$0 --force' to force repin."
        exit 0
    fi
    echo "Repinning all crates"
    CARGO_BAZEL_REPIN=true bazel build @crate_index//...
else
    # CARGO_BAZEL_REPIN takes a single crate, so repin them one at a time.
    for crate in "${CRATES[@]}"; do
        echo "Repinning crate: $crate"
        CARGO_BAZEL_REPIN="$crate" bazel build @crate_index//...
    done
fi
