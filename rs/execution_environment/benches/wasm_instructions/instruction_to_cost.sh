#!/bin/sh
# Uses the `WASM_BENCHMARKS.md` and `WASM_COVERAGE.md` reports to produce
# a Rust code snippet to be used in the `instruction_to_cost` function.
#
# Usage: instruction_to_cost.sh

# Assume the reports are in the same directory as the script.
WASM_BENCHMARKS_FILE="${0%/*}/WASM_BENCHMARKS.md"
WASM_COVERAGE_FILE="${0%/*}/WASM_COVERAGE.md"

# Expect lines with at least 3 columns in the coverage report.
cat "${WASM_COVERAGE_FILE}" | rg "^\| [a-z]" | while read I proposal I op I instr _rest; do
    cost=$(rg -Fw "${instr}" "${WASM_BENCHMARKS_FILE}" | head -1 | awk '{print $6}')
    if [ -n "${cost}" ]; then
        # The comment might be used in the future to automatically update the cost.
        echo "Operator::${op} { .. } => ${cost},"
    else
        echo "// The \`Operator::${op}\` is not covered with benchmarks."
    fi
done
