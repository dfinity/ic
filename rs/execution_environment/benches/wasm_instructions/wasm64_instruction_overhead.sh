#!/bin/bash

### This script measures the overhead of Wasm64 instructions compared to their correspoding Wasm32 instructions.

# The output will be a markdown file with the following columns:
# | Instruction | Wasm32 Time (ns) | Wasm64 Time (ns) | Overhead (%) |

# The overhead is computed as (Wasm64 Time - Wasm32 Time) / Wasm32 Time * 100.

BENCHMARKS_FILE="WASM_BENCHMARKS.md"
# The file has the results of the last benchmark, which look like these:
# wasm32/memop/i32.load                    |    2993245 |    1 |
# wasm64/memop/i32.load                    |    5098896 |    2 |
# wasm32/memop/i64.load                    |    3111268 |    1 |
# wasm64/memop/i64.load                    |    4794852 |    2 |

# The opcodes that are of most interest for computing the overhead.
# One can add other operations, like `memop`, `ibinop`, `fbinop`, etc.
# Check the `WASM_BENCHMARKS.md` file for the complete list of operations.
OP_TYPES="memop vmem"

forty_dashes="----------------------------------------"
eighteen_dashes="----------------"

# Print the header using printf to have a better formatting for the length of the columns.
printf "| %-40s | %-18s | %-18s | %-18s |\n" $forty_dashes $eighteen_dashes $eighteen_dashes $eighteen_dashes
printf "| %-40s | %-18s | %-18s | %-18s |\n" "Instruction" "Wasm32 Time (ns)" "Wasm64 Time (ns)" "Overhead (%)"
printf "| %-40s | %-18s | %-18s | %-18s |\n" $forty_dashes $eighteen_dashes $eighteen_dashes $eighteen_dashes

for op in $OP_TYPES; do
    cat "${BENCHMARKS_FILE}" | grep $op | grep "wasm64" | while read -r line; do
        # Extract the opcode and remove the "wasm64/" prefix.
        opcode=$(echo $line | awk '{print $1}' | sed 's/wasm64\///')

        # Extract the Wasm64 time
        wasm64_time=$(echo $line | awk '{print $3}')
        # Extract the Wasm32 time
        # Some operations are named "memop/i32.load8_s", we need to differentiate these from "memop/i32.load" when grepping.
        wasm32_time=$(cat "${BENCHMARKS_FILE}" | grep "wasm32" | grep -w "${opcode}" | awk '{print $3}')
        # Compute the overhead
        overhead=$(echo "scale=2; (($wasm64_time - $wasm32_time) / $wasm32_time) * 100" | bc -l)
        # Print the results
        printf "| %-40s | %-18s | %-18s | %-18s |\n" "$opcode" "$wasm32_time" "$wasm64_time" "$overhead"
    done
done

printf "| %-40s | %-18s | %-18s | %-18s |\n" $forty_dashes $eighteen_dashes $eighteen_dashes $eighteen_dashes
