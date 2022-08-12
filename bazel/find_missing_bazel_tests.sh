#!/bin/bash

if [ $# -ne 1 ]; then
    echo "USAGE: $0 [subfolder of ic/rs/]"
    exit 1
fi

WORKSPACE_DIR=$(bazel info workspace 2>/dev/null)
echo "--- Checking BUILD.bazel files in $WORKSPACE_DIR/rs/$1/..."
for f in $(find $WORKSPACE_DIR/rs/$1/ -name BUILD.bazel); do
    if ! grep -q rust_test $f; then
        echo "Possibly missing tests in $f"
    fi
done
