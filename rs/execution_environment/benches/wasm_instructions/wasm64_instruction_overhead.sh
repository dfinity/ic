#!/bin/bash

### This script measures the overhead of Wasm64 instructions compared to their correspoding Wasm32 instructions.

# The output will be a markdown file with the following columns:
# | Instruction | Wasm32 Time (ns) | Wasm64 Time (ns) | Overhead (%) |

# The overhead is computed as (Wasm64 Time - Wasm32 Time) / Wasm32 Time * 100.

WASM32_FILE="WASM_BENCHMARKS.md"
WASM64_FILE="WASM64_BENCHMARKS.md"

# The opcodes that are of most interest for computing the overhead.
# One can add other operations, like `memop`, `ibinop`, `fbinop`, etc.
# Check the `WASM_BENCHMARKS.md` file for the complete list of operations.
OP_TYPES="memop"

# Print the header using printf to have a better formatting for the length of the columns.
printf "| %-20s | %-18s | %-18s | %-18s |\n" "--------------------" "------------------" "------------------" "------------------"
printf "| %-20s | %-18s | %-18s | %-18s |\n" "Instruction" "Wasm32 Time (ns)" "Wasm64 Time (ns)" "Overhead (%)"
printf "| %-20s | %-18s | %-18s | %-18s |\n" "--------------------" "------------------" "------------------" "------------------"

for op in $OP_TYPES; do
    cat "${WASM64_FILE}" | grep $op | while read -r line; do
        # Extract the opcode
        opcode=$(echo $line | awk '{print $1}')
        # Extract the Wasm64 time
        wasm64_time=$(echo $line | awk '{print $3}')
        # Extract the Wasm32 time
        # Some operations are named "memop/i32.load8_s", we need to differentiate these from "memop/i32.load" when grepping.
        wasm32_time=$(cat "${WASM32_FILE}" | grep -w "${opcode}" | awk '{print $4}')
        # Compute the overhead
        overhead=$(echo "scale=2; (($wasm64_time - $wasm32_time) / $wasm32_time) * 100" | bc)
        # Print the results
        printf "| %-20s | %-18s | %-18s | %-18s |\n" "$opcode" "$wasm32_time" "$wasm64_time" "$overhead"
    done
done

printf "| %-20s | %-18s | %-18s | %-18s |\n" "--------------------" "------------------" "------------------" "------------------"
