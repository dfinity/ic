#!/bin/sh
# Uses the list of `wasmparser` supported Wasm proposals, Wasm instructions
# benchmarks and Wasm instructions costs defined in the `ic` repo to produce
# a Wasm instructions coverage report in Markdown format (see `WASM_COVERAGE.md`)
#
# Usage: wasm_coverage.sh

# The file with basic Wasm instruction benchmarks.
BASIC_BENCHES_FILE="${0%/*}/../wasm_instructions/basic.rs"
# The file with Wasm SIMD instruction benchmarks.
SIMD_BENCHES_FILE="${0%/*}/../wasm_instructions/simd.rs"
# The file with `instruction_to_cost` function.
INSTRUCTION_TO_COST_FILE="${0%/*}/../../../embedders/src/wasm_utils/instrumentation.rs"
# The file with Wasm proposal to Wasm operator mapping.
PROPOSAL_TO_OP_URL="https://raw.githubusercontent.com/bytecodealliance/wasm-tools/main/crates/wasmparser/src/lib.rs"
# The file with Wasm operator to Wasm instruction mapping.
OP_TO_INSTR_URL="https://raw.githubusercontent.com/bytecodealliance/wasm-tools/main/crates/wast/src/core/expr.rs"
# The Wasm proposal to exclude from the coverage, i.e. unsupported Wasm proposals.
EXCLUDE_PROPOSALS="relaxed_simd|threads|multi_memory|exceptions|memory64|extended_const|component_model|function_references|memory_control|gc|shared_everything_threads"

# Extract `instruction_to_cost` function from the file.
instruction_to_cost=$(sed -n '/pub fn instruction_to_cost/,/^[}]/{p}' "${INSTRUCTION_TO_COST_FILE}")

# Download mapping files.
proposal_to_op=$(curl --silent "${PROPOSAL_TO_OP_URL}")
op_to_instr=$(curl --silent "${OP_TO_INSTR_URL}")

# We're looking for the lines like `@mvp I32Load { memarg: $crate::MemArg } => visit_i32_load`
echo "${proposal_to_op}" | rg '^ *@[a-z]' | rg -v "^ *@(${EXCLUDE_PROPOSALS}) " | while read proposal op _rest; do
    # We're looking for the lines like `If(Box<BlockType<'a>>) : [0x04] : "if"`
    instr=$(echo "${op_to_instr}" | rg -i "^ *${op}[ (].*[:] .* [:] " | cut -d ':' -f 3 | sed -Ee 's/^[ "]*//' -e 's/["].*//')
    instr=$([ -n "${instr}" ] && echo "${instr}" || echo "NO INSTR")

    NO_BASIC_BENCH=$(rg -qw "${instr}" "${BASIC_BENCHES_FILE}" && echo "" || echo "NO BASIC BENCH")
    NO_SIMD_BENCH=$(rg -qw "${instr}" "${SIMD_BENCHES_FILE}" && echo "" || echo "NO SIMD BENCH")
    NO_BENCH=$([ -z "${NO_BASIC_BENCH}" -o -z "${NO_SIMD_BENCH}" ] && echo "" || echo "NO BENCH")
    NO_COST=$(echo "${instruction_to_cost}" | rg -qw "${op}" && echo "" || echo "NO COST")

    printf "%-23s | %-25s | %-29s | %-8s | %-7s\n" \
        "${proposal#@}" "${op}" "${instr}" "${NO_BENCH}" "${NO_COST}"
done
