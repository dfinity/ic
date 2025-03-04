#!/usr/bin/env bash
set -eEuo pipefail

bazel query --universe_scope=//... \
    "kind(test, //rs/...) except kind(test, allrdeps(attr('tags', 'canister', //rs/...)))" \
    >cov_targets.txt

# exclude the target below because of flaky builds - https://github.com/dfinity/ic/pull/2103
sed -i '/minter:principal_to_bytes_test/d' cov_targets.txt
# shellcheck disable=SC2046,SC2086
bazel --output_base=/var/tmp/bazel-output/ coverage --config=ci --combined_report=lcov \
    --test_timeout=3000 --combined_report=lcov $(<cov_targets.txt) || true
# some tests may fail, but we still want to generate coverage report
cp bazel-out/_coverage/_coverage_report.dat cov_report.dat
genhtml --output cov_html cov_report.dat

# Zip all files in the cov_html directory
zip -r cov_html.zip cov_html
