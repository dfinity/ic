#!/usr/bin/env bash
# A utility script to run all fuzzers on IC for limited turns defined under MAX_EXECUTIONS
set -ex

MAX_EXECUTIONS=100
if [[ -n "$2" ]]; then
    MAX_EXECUTIONS=$2
fi

case $1 in
    -h | --help)
        cat <<EOF >&2
        usage:
            $0 --libfuzzer 100 # Run all libfuzzer targets. Each target will have 100 executions.
            $0 --afl 100       # Run all afl targets. Each target will have 100 executions.
EOF
        exit 0
        ;;
    --libfuzzer)
        bazel build --config=lint --config=fuzzing --build_tag_filters=libfuzzer //rs/...
        LIST_OF_FUZZERS=$(bazel query 'attr(tags, "libfuzzer", //rs/...) except attr(tags, "sandbox_libfuzzer", //rs/...)')
        for FUZZER in $LIST_OF_FUZZERS; do
            bazel run --config=fuzzing $FUZZER -- -runs=$MAX_EXECUTIONS
        done
        LIST_OF_FUZZERS=$(bazel query 'attr(tags, "sandbox_libfuzzer", //rs/...)')
        for FUZZER in $LIST_OF_FUZZERS; do
            bazel run --config=sandbox_fuzzing $FUZZER -- -runs=$MAX_EXECUTIONS
        done
        ;;

    --afl)
        LIST_OF_FUZZERS=$(bazel query 'attr(tags, "afl", //rs/...)')
        bazel build --config=lint --config=afl //rs/...
        for FUZZER in $LIST_OF_FUZZERS; do
            AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 bazel run --config=afl $FUZZER -- -E $MAX_EXECUTIONS
        done
        ;;
esac
