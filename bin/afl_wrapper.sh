#!/usr/bin/env bash

# This is only meant to test if the afl binary built is working
# by adding a dummy testcase. To get meaningful results, the input
# directory must be a valid corpus.

set -x

# If you would like to include your own corpus,
# export INPUT_DIR=/path/to/corpus
if [[ -z "$INPUT_DIR" ]]; then
    INPUT_DIR=$(mktemp -d)
    echo "A dummy corpus file to make AFL work" >$INPUT_DIR/seed_corpus.txt
fi

# Output directory
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR=$(mktemp -d)
fi

cleanup() {
    echo "Input directory ${INPUT_DIR}"
    echo "Output directory ${OUTPUT_DIR}"

    # kill all detached fuzzers
    ps -ax | grep afl | awk '{print $1}' | xargs -I {} kill -9 {}
}

trap cleanup EXIT

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

function afl_env() {
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

    # Keep them sorted
    ASAN_OPTIONS=$ASAN_OPTIONS \
        LSAN_OPTIONS=$LSAN_OPTIONS \
        AFL_CMPLOG_ONLY_NEW=1 \
        AFL_DEBUG_CHILD=1 \
        AFL_DISABLE_TRIM=1 \
        AFL_DRIVER_DONT_DEFER=1 \
        AFL_EXPAND_HAVOC_NOW=1 \
        AFL_FAST_CAL=1 \
        AFL_FORKSRV_INIT_TMOUT=100 \
        AFL_IGNORE_PROBLEMS=1 \
        AFL_IGNORE_TIMEOUTS=1 \
        AFL_KEEP_TIMEOUTS=1 \
        AFL_SKIP_CPUFREQ=1 \
        /usr/local/bin/afl-fuzz -t +20000 $@
}

# To run multiple fuzzers in parallel, use the AFL_PARALLEL env variable
# export AFL_PARALLEL=4
# Make sure you have enough cores, as each job occupies a core.

if [[ ! -z "$AFL_PARALLEL" ]]; then
    # master fuzzer
    afl_env -i $INPUT_DIR -o $OUTPUT_DIR -P exploit -p explore -M fuzzer1 ${@:2} -- $1 </dev/null &>/dev/null &

    for i in $(seq 2 $AFL_PARALLEL); do
        probability=$((100 * $i / $AFL_PARALLEL))

        # Strategy distribution
        # 0.34 - exploit
        # 0.67 - explore

        # Power Schedule distribution
        # 0.3 - fast
        # 0.3 - explore
        # 0.2 - exploit
        # 0.1 - coe
        # 0.1 - rare

        # cummulative sum probability
        if [[ $probability -le 10 ]]; then
            power_schedule="fast"
            strategy="exploit"
        elif [[ $probability -le 30 ]]; then
            power_schedule="fast"
            strategy="explore"
        elif [[ $probability -le 40 ]]; then
            power_schedule="explore"
            strategy="exploit"
        elif [[ $probability -le 60 ]]; then
            power_schedule="explore"
            strategy="explore"
        elif [[ $probability -le 67 ]]; then
            power_schedule="exploit"
            strategy="exploit"
        elif [[ $probability -le 80 ]]; then
            power_schedule="exploit"
            strategy="explore"
        elif [[ $probability -le 84 ]]; then
            power_schedule="coe"
            strategy="exploit"
        elif [[ $probability -le 90 ]]; then
            power_schedule="coe"
            strategy="explore"
        elif [[ $probability -le 94 ]]; then
            power_schedule="rare"
            strategy="exploit"
        else
            power_schedule="rare"
            strategy="explore"
        fi

        afl_env -i $INPUT_DIR -o $OUTPUT_DIR -P $strategy -p $power_schedule -S fuzzer$i ${@:2} -- $1 </dev/null &>/dev/null &
    done

    watch -n 5 --color "afl-whatsup -s -d $OUTPUT_DIR"
else
    # if AFL_PARALLEL is not set
    # run a single instance
    # single instance will mimic the master fuzzer
    afl_env -i $INPUT_DIR -o $OUTPUT_DIR -P exploit -p explore ${@:2} -- $1
fi
