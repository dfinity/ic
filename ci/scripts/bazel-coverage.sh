#!/usr/bin/env bash
set -eEuo pipefail

bazel query --universe_scope=//... \
    "kind(test, //rs/...) except kind(test, allrdeps(attr('tags', 'canister', //rs/...)))" \
    >cov_targets.txt

# shellcheck disable=SC2046,SC2086
bazel --output_base=/var/tmp/bazel-output/ coverage --config=ci --combined_report=lcov \
    --test_timeout=3000 --combined_report=lcov $(<cov_targets.txt) || true
cp bazel-out/_coverage/_coverage_report.dat cov_report.dat
genhtml --output cov_html cov_report.dat

# upload report to s3
rclone sync cov_html public-s3://dfinity-download-public/coverage/${CI_COMMIT_SHA}/ \
    --config .rclone.conf

# rint url as log and annotation
URL="https://download.dfinity.systems/coverage/$CI_COMMIT_SHA/index.html"
echo "Code Coverage Report [$CI_COMMIT_SHA]($URL)" >>$GITHUB_STEP_SUMMARY
echo "Code Coverage Report: $URL"
