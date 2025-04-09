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

ASAN_OPTIONS="abort_on_error=1:\
            alloc_dealloc_mismatch=0:\
            allocator_may_return_null=1:\
            allocator_release_to_os_interval_ms=500:\
            allow_user_segv_handler=1:\
            check_malloc_usable_size=0:\
            detect_leaks=0:\
            detect_odr_violation=0:\
            detect_stack_use_after_return=1:\
            fast_unwind_on_fatal=0:\
            handle_abort=2:\
            handle_segv=1:\
            handle_sigbus=2:\
            handle_sigfpe=1:\
            handle_sigill=0:\
            max_uar_stack_size_log=16:\
            print_scariness=1:\
            print_summary=1:\
            print_suppressions=0:\
            quarantine_size_mb=64:\
            redzone=512:\
            strict_memcmp=1:\
            symbolize=0:\
            use_sigaltstack=1"

LSAN_OPTIONS="handle_abort=1:\
            handle_segv=1:\
            handle_sigbus=1:\
            handle_sigfpe=1:\
            handle_sigill=0:\
            print_summary=1:\
            print_suppressions=0:\
            symbolize=0:\
            use_sigaltstack=1"

# Perform corpus minimization
WORKSPACE=$(bazel info workspace --ui_event_filters=-WARNING,-INFO 2>/dev/null)
TARGET_PREFIX="//rs/embedders/fuzz"
for i in "${TARGETS[@]}"; do
    FUZZER="$TARGET_PREFIX:$i"
    bazel build --config=afl $FUZZER
    SOURCE_BINARY="$WORKSPACE/$(bazel cquery --config=afl --output=files $FUZZER)"
    # Minimum 8 cores is assumed
    ASAN_OPTIONS=$ASAN_OPTIONS LSAN_OPTIONS=$LSAN_OPTIONS afl-cmin -i $TEMP_DIR -o $OUTPUT_DIR/$i -T 8 -t 20000 -- $SOURCE_BINARY @@
done
