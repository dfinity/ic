#!/usr/bin/env bash

set -euo pipefail

print_blue() {
    echo -e "\033[1;34m$*\033[0m"
}

print_red() {
    echo -e "\033[0;31m$*\033[0m"
}

REPO_DIR="$(git rev-parse --show-toplevel)"
mkdir -p "${REPO_DIR}/artifacts"

print_blue ":: Cargo Tests ::"
pushd "${REPO_DIR}/rs"
# cargo nextest gives us nice output of "package->test-list"
cargo nextest list --all-features --run-ignored all | tee "${REPO_DIR}/artifacts/cargo-nextest.out"
# sanitize the data
sed -i 's/:$//' "${REPO_DIR}/artifacts/cargo-nextest.out"
# cargo nextest doesn't support doc tests, get them with `cargo test --doc`
cargo test --doc -- --list 2>&1 | tee "${REPO_DIR}/artifacts/cargo-doc-tests.out"
# sanitize the data
sed -i 's/: test$//' "${REPO_DIR}/artifacts/cargo-doc-tests.out"
popd

print_blue ":: Bazel Tests ::"
# `bazel test` gives us all the tests, we only need to build them and not run them
if ! bazel test --config=ci --config=alltests --test_arg=--list \
    --build_tests_only --ui_event_filters=-debug --noshow_progress --test_lang_filters=-py \
    --test_output=all --output_groups=-clippy_checks --keep_going //rs/... 2>&1 | tee "${REPO_DIR}/artifacts/bazel.out"; then
    print_red "Some tests seemed to fail. We only care about complete list of tests so we assume this is not fatal."
fi

pushd "${REPO_DIR}/artifacts"
egrep '^[A-Za-z0-9_:]*: test|Test output for' bazel.out >bazel.tests
# sanitize the data
sed -i -e '$!N;/^=.*\n=/D' -e 'P;D' bazel.tests
sed -i 's/ test$//' bazel.tests
sed -i 's/:$//' bazel.tests

egrep '\(line|Test output for' bazel.out >bazel.doc-tests
# sanitize the data
sed -i -e '$!N;/^=.*\n=/D' -e 'P;D' bazel.doc-tests
sed -i 's/test \(rs.*)\) .*$/\1/' bazel.doc-tests
sed -i 's/:$//' bazel.doc-tests

# The following list of files is now ready for parity analysis with `compare_covered_tests.py` script
# * cargo-nextest.out   ~ sanitized `cargo nextest list` output
# * cargo-doc-tests.out ~ sanitized `cargo test --doc` output
# * bazel.tests         ~ sanitized and filtered doc tests from `bazel test`
# * bazel.doc-tests     ~ sanitized and filtered tests from `bazel test`

print_blue ":: Analysing Test Parity ::"
../bazel/test_parity/compare_covered_tests.py ../bazel/test_parity/ignored.tests ../bazel/test_parity/ignored.doctests
