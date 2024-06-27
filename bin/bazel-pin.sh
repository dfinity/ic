#!/usr/bin/env bash

set -euo pipefail

if [ -n "${IN_NIX_SHELL:-}" ]; then
    echo "Please do not run $0 inside of nix-shell." >&2
    exit 1
fi

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
    cat <<EOF >&2
    usage:

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
    exit 0
fi

if [[ $# -eq 0 ]]; then
    echo "Repinning all crates"
    CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
    #SANITIZERS_ENABLED=1 CARGO_BAZEL_REPIN=1 bazel sync --only=crate_index
else
    for crate in "$@"; do
        echo "Repinning crate: ${crate}"
        CARGO_BAZEL_REPIN="${crate}" bazel sync --only=crate_index
        #SANITIZERS_ENABLED=1 CARGO_BAZEL_REPIN="${crate}" bazel sync --only=crate_index
    done
fi
