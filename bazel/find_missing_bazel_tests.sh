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
    has_unit_tests="false"
    has_integration_tests="false"
    if grep -q -r -s '#[[]test[]]' $CRATE_DIR/src; then
        has_unit_tests="true"
    fi
    if grep -q -r -s '#[[]test[]]' $CRATE_DIR/tests; then
        has_integration_tests="true"
    fi

    if [[ ($has_unit_tests == "true") || ($has_integration_tests == "true") ]]; then
        echo "     FOUND tests in the crate, comparing cargo and bazel coverage..."
        cd $CRATE_DIR
        $COMPARE_COVERED_TESTS 2>/dev/null
    else
        echo "     no tests in the crate, skipping."
    fi
done
