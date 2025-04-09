#!/usr/bin/env bash

# Run AFL based target against a single input

set -x

# Usage
# ./bin/afl_test.sh //rs/embedders/fuzz:execute_with_wasm_executor_afl /path/to/testcase

AFL_BAZEL_TARGET=$1
TEST_INPUT=$2

WORKSPACE=$(bazel info workspace --ui_event_filters=-WARNING,-INFO 2>/dev/null)

# This allows us to skip false positive crashes for wasm runtime
if [[ "$1" == *"wasmtime"* ]] || [[ "$1" == *"wasm_executor"* ]]; then
    # We handle segv for wasm execution
    ALLOW_USER_SEGV_HANDLER=1
    # SIGILL is used to handle unreachable
    HANDLE_SIGILL=0
    HANDLE_SEGV=1
    HANDLE_SIGFPE=1
else
    ALLOW_USER_SEGV_HANDLER=0
    HANDLE_SIGILL=2
    HANDLE_SEGV=2
    HANDLE_SIGFPE=2
fi

ASAN_OPTIONS="abort_on_error=1:\
            alloc_dealloc_mismatch=0:\
            allocator_may_return_null=1:\
            allocator_release_to_os_interval_ms=500:\
            allow_user_segv_handler=$ALLOW_USER_SEGV_HANDLER:\
            check_malloc_usable_size=0:\
            detect_leaks=0:\
            detect_odr_violation=0:\
            detect_stack_use_after_return=1:\
            fast_unwind_on_fatal=0:\
            handle_abort=2:\
            handle_segv=$HANDLE_SEGV:\
            handle_sigbus=2:\
            handle_sigfpe=$HANDLE_SIGFPE:\
            handle_sigill=$HANDLE_SIGILL:\
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
            handle_sigill=$HANDLE_SIGILL:\
            print_summary=1:\
            print_suppressions=0:\
            symbolize=0:\
            use_sigaltstack=1"

bazel build --config=afl $AFL_BAZEL_TARGET
AFL_BINARY="$WORKSPACE/$(bazel cquery --config=fuzzing --output=files $AFL_BAZEL_TARGET)"
ASAN_OPTIONS=$ASAN_OPTIONS LSAN_OPTIONS=$LSAN_OPTIONS $AFL_BINARY $TEST_INPUT
