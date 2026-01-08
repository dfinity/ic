#!/usr/bin/env bash
set -eEuo pipefail

# Ensure lcov is installed
if ! command -v lcov >/dev/null 2>&1; then
    echo "lcov not found, installing..."
    sudo apt-get update && sudo apt-get install -y lcov
fi

bazel query --universe_scope=//... \
    "kind(test, //rs/...) except kind(test, allrdeps(attr('tags', 'canister', //rs/...)))" \
    >cov_targets.txt

# shellcheck disable=SC2046,SC2086
bazel --output_base=/var/tmp/bazel-output/ coverage --combined_report=lcov \
    --test_timeout=3000 --combined_report=lcov $(<cov_targets.txt) || true
# some tests may fail, but we still want to generate coverage report
cp bazel-out/_coverage/_coverage_report.dat cov_report.dat
genhtml --output cov_html cov_report.dat

# Zip all files in the cov_html directory
zip -r cov_html.zip cov_html
