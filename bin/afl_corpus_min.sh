#!/usr/bin/env bash

# AFL Corpus minimizer
# !NOTE: This script is only meant to be used for fuzzers that utilize ICWasmModule as input.
# The targets currently supported are
# - //rs/embedders/fuzz:execute_with_wasmtime_afl
# - //rs/embedders/fuzz:execute_with_wasm_executor_afl
# - //rs/embedders/fuzz:differential_simd_execute_with_wasmtime_afl

set -x

# Usage
# ./bin/afl_corpus_min.sh /input/dir /output/dir

# Output directory of last fuzzing run
# This will be our source of new corpus
INPUT_DIR=$1

if [[ -z "$INPUT_DIR" ]]; then
    echo "Input directory is not set"
    exit 1
fi

# Output directory of previous minimized corpus
# This will be the source of old corpus and where the new minimized corpus
# will be preserved
OUTPUT_DIR=$2

if [[ -z "$OUTPUT_DIR" ]]; then
    echo "Output directory is not set"
    exit 1
fi

TEMP_DIR=$(mktemp -d)
declare -a TARGETS=("execute_with_wasmtime_afl" "execute_with_wasm_executor_afl" "differential_simd_execute_with_wasmtime_afl")

# Move new corpus from INPUT_DIR
# It's fine to overshoot number of fuzzers here
for i in $(seq 1 64); do
    cp -R $INPUT_DIR/fuzzer$i/queue/* $TEMP_DIR
done

# Move exisitng corpus from OUTPUT_DIR
# Running minimization will recreate the new files
if [ -z "$(ls $OUTPUT_DIR)" ]; then
    echo "Output directory is empty. Bootstrapping"
    for i in "${TARGETS[@]}"; do
        mkdir -p $OUTPUT_DIR/$i
    done
else
    echo "Output directory is not empty. Moving files to $TEMP_DIR"
    for i in "${TARGETS[@]}"; do
        cp -R $OUTPUT_DIR/$i/* $TEMP_DIR
        rm -r $OUTPUT_DIR/$i/*
    done
fi

# Perform corpus minimization
WORKSPACE=$(bazel info workspace --ui_event_filters=-WARNING,-INFO 2>/dev/null)
TARGET_PREFIX="//rs/embedders/fuzz"
for i in "${TARGETS[@]}"; do
    FUZZER="$TARGET_PREFIX:$i"
    SOURCE_BINARY="$WORKSPACE/$(bazel cquery --config=afl --output=files $FUZZER)"
    # Minimum 8 cores is assumed
    afl-cmin -i $TEMP_DIR -o $OUTPUT_DIR/$i -T 8 -t 20000 -- $SOURCE_BINARY @@
done
