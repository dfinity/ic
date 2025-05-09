#!/usr/bin/env bash

set -x

show_help() {
    cat <<EOF
AFL Corpus Minimizer

This script is intended for use with fuzzers that accept ICWasmModule as input.
It minimizes AFL fuzzing corpora across multiple targets.

Supported targets:
  //rs/embedders/fuzz:execute_with_wasmtime_afl
  //rs/embedders/fuzz:execute_with_wasm_executor_afl
  //rs/embedders/fuzz:differential_simd_execute_with_wasmtime_afl

Usage:
  $0 /path/to/input/dir /path/to/output/dir

Arguments:
  input_dir     Directory containing output from the latest fuzzing run
  output_dir    Directory to write the minimized corpus to
EOF
    exit 0
}

# Show help if -h or --help is passed
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
fi

# Input directory containing corpus from the latest fuzzing run
INPUT_DIR=$1

if [[ -z "$INPUT_DIR" ]]; then
    echo "Input directory is not set"
    exit 1
fi

# Output directory for storing the minimized corpus
# It may contain previously minimized corpus files
OUTPUT_DIR=$2

if [[ -z "$OUTPUT_DIR" ]]; then
    echo "Output directory is not set"
    exit 1
fi

TEMP_DIR=$(mktemp -d)
declare -a TARGETS=("execute_with_wasmtime_afl" "execute_with_wasm_executor_afl" "differential_simd_execute_with_wasmtime_afl")

# Copy the new corpus from INPUT_DIR
# It's fine if some fuzzer directories don't exist
for i in $(seq 1 64); do
    cp -R "$INPUT_DIR/fuzzer$i/queue/"* "$TEMP_DIR" 2>/dev/null || true
done

# Copy the existing minimized corpus from OUTPUT_DIR if available
# Otherwise, create target-specific subdirectories to bootstrap
if [ -z "$(ls $OUTPUT_DIR)" ]; then
    echo "Output directory is empty. Bootstrapping..."
    for target in "${TARGETS[@]}"; do
        mkdir -p $OUTPUT_DIR/$target
    done
else
    echo "Output directory is not empty. Moving files to temporary directory $TEMP_DIR ..."
    for target in "${TARGETS[@]}"; do
        cp -R $OUTPUT_DIR/$target/* $TEMP_DIR
        # AFL has issues with directory not being clean
        rm -rf $OUTPUT_DIR/$target/
        mkdir -p $OUTPUT_DIR/$target
    done
fi

# ASan and LSan options to capture false positives and runtime errors
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

SHOWMAP_TEMPFILE=$(mktemp)
# This file result will be pushed to STDOUT before the script exits
SHOWMAP_SUMMARY_TEMPFILE=$(mktemp)

# Perform corpus minimization for each target
WORKSPACE=$(bazel info workspace --ui_event_filters=-WARNING,-INFO 2>/dev/null)
TARGET_PREFIX="//rs/embedders/fuzz"
for target in "${TARGETS[@]}"; do
    FUZZER="$TARGET_PREFIX:$target"
    bazel build --config=afl $FUZZER
    SOURCE_BINARY="$WORKSPACE/$(bazel cquery --config=afl --output=files $FUZZER)"
    # Minimum 8 cores is assumed
    ASAN_OPTIONS=$ASAN_OPTIONS LSAN_OPTIONS=$LSAN_OPTIONS afl-cmin.bash -i $TEMP_DIR -o $OUTPUT_DIR/$target -T 8 -t 20000 -- $SOURCE_BINARY @@
    ASAN_OPTIONS=$ASAN_OPTIONS LSAN_OPTIONS=$LSAN_OPTIONS afl-showmap -i $OUTPUT_DIR/$target -o $SHOWMAP_TEMPFILE -C -- $SOURCE_BINARY @@ >>$SHOWMAP_SUMMARY_TEMPFILE
    # Rename minimized corpus files to SHA256 hashes
    for filename in "$OUTPUT_DIR/$target"/*; do
        if [[ -f "$filename" ]]; then
            hash=$(sha256sum "$filename" | awk '{print $1}')
            mv -f "$filename" "$OUTPUT_DIR/$target/$hash"
        fi
    done
done

echo "Coverage results"
cat $SHOWMAP_SUMMARY_TEMPFILE
