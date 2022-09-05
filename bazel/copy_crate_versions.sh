#!/bin/bash

if [ $# -ne 1 ]; then
    echo "USAGE: $0 [subfolder of ic/rs/]"
    exit 1
fi

print_purple() {
    echo -e "\033[1;35m$*\033[0m"
}

WORKSPACE_DIR=$(bazel info workspace 2>/dev/null)
SCRIPT=$(realpath "$0")
COMPARE_COVERED_TESTS="$(dirname "$SCRIPT")/compare_covered_tests.sh"
echo "**** Checking BUILD.bazel files in $WORKSPACE_DIR/rs/$1/..."
echo "     using $COMPARE_COVERED_TESTS to compare covered tests."
for f in $(find $WORKSPACE_DIR/rs/$1 -name BUILD.bazel); do
    CRATE_DIR="$(dirname "${f}")"
    print_purple "==== checking crate $CRATE_DIR"
    CRATE_NAME=$(grep '^name =' "$CRATE_DIR/Cargo.toml" | head -1 | cut -d ' ' -f 3 | sed -r 's/-/_/g')
    CRATE_VERSION=$(grep '^version =' "$CRATE_DIR/Cargo.toml" | cut -d ' ' -f 3)
    if grep -q "crate_name = $CRATE_NAME," "$CRATE_DIR/BUILD.bazel"; then
        echo "    setting version $CRATE_VERSION for $CRATE_NAME"
        sed -i "s/crate_name = $CRATE_NAME,/crate_name = $CRATE_NAME,\n    version = $CRATE_VERSION,/" "$CRATE_DIR/BUILD.bazel"
        cd $CRATE_DIR
        bazel run //:buildifier
    fi
done
