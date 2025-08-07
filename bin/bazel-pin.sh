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
  $0 [--force] [PACKAGE...]

Options:
  --force       will repin even if repin is not deemed necessary
EOF
}

function help() {
    cat <<EOF
    All packages:
        $0                    # cargo update --workspace

    Single package:
        $0 package_name       # cargo upgrade --package package_name
        $0 package_name@1.2.3 # cargo upgrade --package package_name --precise 1.2.3

    Multiple packages:
        You can provide multiple package names (separated by spaces) to repin several crates at once.
        Package names can be followed by @version to specify a particular version.

        Examples:
            $0 package1 package2  # cargo upgrade --package package1 and package2
            $0 package1@1.2.3 package2@1.3.4 # cargo upgrade --package package1 and package2 with specified versions

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

if [ $FORCE_REPIN != "1" ] && bazel query @crate_index//:all >/dev/null; then
    # If this isn't a forced repin and if rules_rust still evaluates successfully (using
    # bazel query as a proxy) then we don't need to do anything
    echo "Nothing to repin. Use '$0 --force' to force repin."
    exit 0
fi

if [ "${CRATES:-}" == "" ]; then
    echo "Repinning all crates"
    CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
else
    echo "Repinning ${#CRATES[@]} crates"
    for crate in "${CRATES[@]}"; do
        echo "Repinning crate: ${crate}"
        CARGO_BAZEL_REPIN="${crate}" bazel sync --only=crate_index
    done
fi
