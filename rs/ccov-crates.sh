#!/bin/sh
##
## Generate Code Coverage for Crates
## Based on: https://doc.rust-lang.org/nightly/rustc/instrument-coverage.html
##
## Note: if a crate is covered with integration test in another crate,
##       both crates must be tested at the same time.
## For example, running the script just for `embedders` gives 67.67% of coverage:
##     ./ccov-crates.sh embedders
## But running it together with `execution_environment gives 82.57% of `embedders` coverage:
##     ./ccov-crates.sh embedders execution_environment
##

CRATES=${*:?Usage: ${0##*/} CRATE1 [CRATE2]...}

echo "==> Deleting old profiling data..."
find . -name "ccov-*.profraw" -delete

echo "==> Installing required components in parallel..."
(
    cargo install rustfilt
    cargo install cargo-binutils
    rustup component add llvm-tools-preview
) 2>&1 | tee "ccov-install.log" | sed "s#^\s*#install:\t#" &

echo "==> Running cargo tests in parallel..."
for crate in ${CRATES}; do
    (
        cd "${crate}" \
            && RUSTFLAGS="-C instrument-coverage" \
                LLVM_PROFILE_FILE="ccov-%m.profraw" \
                cargo test
    ) 2>&1 | tee "${crate}.log" | rg -v "test .* ok|^$" | sed "s#^\s*#${crate}:\t#" &
done
wait

echo "==> Merging all raw profiler files into ccov.profdata..."
profraws=$(find . -name "ccov-*.profraw")
cargo profdata -- merge -sparse ${profraws} -o "ccov.profdata"

echo "==> Gathering object files..."
OBJECTS=""
for crate in ${CRATES}; do
    files=$(cat "${crate}.log" | rg "Running" | sed -Ee 's#.*\((.*)\).*#\1#')
    for file in ${files}; do
        echo "    ${crate}:\t${file}"
        OBJECTS="${OBJECTS} --object=${file}"
    done
done

for crate in ${CRATES}; do
    echo "==> Generating ${crate}_coverage_report.txt in parallel..."
    cargo cov -- report ${OBJECTS} \
        --instr-profile="ccov.profdata" \
        --Xdemangler=rustfilt \
        --ignore-filename-regex="\.cargo" \
        --ignore-filename-regex="rustc/" \
        --ignore-filename-regex="tests/" \
        --ignore-filename-regex="testgrid/" \
        --ignore-filename-regex="tests.rs" \
        "" "${crate}" \
        >"${crate}_coverage_report.txt" &
    echo "==> Generating ${crate}_coverage details in parallel..."
    (
        rm -rdf "${crate}_coverage"
        cargo cov -- show ${OBJECTS} \
            --instr-profile="ccov.profdata" \
            --Xdemangler=rustfilt \
            --ignore-filename-regex="\.cargo" \
            --ignore-filename-regex="rustc/" \
            --ignore-filename-regex="tests/" \
            --ignore-filename-regex="testgrid/" \
            --ignore-filename-regex="tests.rs" \
            --show-line-counts-or-regions \
            --format=html \
            --output-dir="${crate}_coverage"
        rm -f "${crate}_coverage.zip"
        zip --move --recurse-paths --quiet "${crate}_coverage.zip" "${crate}_coverage"
    ) &
done
wait
echo "All done."
