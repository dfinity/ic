#!/usr/bin/env bash

# This is only meant to test if the afl binary built is working
# by adding a dummy testcase. To get meaningful results, the input
# directory must be a valid corpus.

set -x
# Create a dummy input directory
# If you would like to include your own corpus,
# INPUT_DIR=/path/to/corpus
INPUT_DIR=$(mktemp -d)
echo "A dummy corpus file to make AFL work" >$INPUT_DIR/seed_corpus.txt

# Output directory
OUTPUT_DIR=$(mktemp -d)

ASAN_OPTIONS="abort_on_error=1:\
            alloc_dealloc_mismach=0:\
            allocator_may_return_null=1:\
            allocator_release_to_os_interval_ms=500:\
            allow_user_segv_handler=0:\
            check_malloc_usable_size=0:\
            detect_leaks=0:\
            detect_odr_violation=0:\
            detect_stack_use_after_return=1:\
            fast_unwind_on_fatal=0:\
            handle_abort=2:\
            handle_segv=2:\
            handle_sigbus=2:\
            handle_sigfpe=2:\
            handle_sigill=2:\
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
            handle_sigill=1:\
            print_summary=1:\
            print_suppressions=0:\
            symbolize=0:\
            use_sigaltstack=1"

ASAN_OPTIONS=$ASAN_OPTIONS \
    LSAN_OPTIONS=$LSAN_OPTIONS \
    AFL_FORKSRV_INIT_TMOUT=100 \
    AFL_FAST_CAL=1 \
    AFL_BENCH_UNTIL_CRASH=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_CMPLOG_ONLY_NEW=1 \
    AFL_IGNORE_PROBLEMS=1 \
    AFL_IGNORE_TIMEOUTS=1 \
    AFL_KEEP_TIMEOUTS=1 \
    AFL_EXPAND_HAVOC_NOW=1 \
    AFL_DRIVER_DONT_DEFER=1 \
    AFL_DISABLE_TRIM=1 \
    /usr/local/bin/afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR ${@:2} -- $1
