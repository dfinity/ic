#!/usr/bin/env bash
set -euo pipefail

case $1 in
    -h | --help)
        cat <<EOF >&2
        $(basename "$0") [-t | -c] [-l | -a] [FUZZING_TARGET] [TEST_INPUT]

        Generate coverage data for fuzzers. Works only inside the devcontainer.
        HTML coverage data will be generated in the genhtml directory.

        Options:
            --testcase,  -t  # Single testcase
            --corpus,    -c  # Directory of multiple testcases
            --libfuzzer, -l  # Libfuzzer based fuzzer
            --afl,       -a  # AFL based fuzzer

        Usage:
            $0 --testcase --libfuzzer //rs/.../fuzz:fuzzing_target path/to/testcase # Generate coverage with single testcase for a libfuzzer based fuzzer 
            $0 --testcase --afl //rs/.../fuzz:fuzzing_target path/to/testcase       # Generate coverage with single testcase for an afl based fuzzer
            $0 --corpus --libfuzzer //rs/.../fuzz:fuzzing_target path/to/corpus/dir # Generate coverage with a corpus directory for a libfuzzer based fuzzer 
            $0 --corpus --afl //rs/.../fuzz:fuzzing_target path/to/corpus/dir       # Generate coverage with a corpus directory for an afl based fuzzer
EOF
        exit 0
        ;;
    --testcase | --corpus | -t | -c)
        WORKSPACE=$(bazel info workspace --ui_event_filters=-WARNING,-INFO 2>/dev/null)
        FUZZING_TARGET=$3
        TEST_INPUT=$4

        case $2 in
            --libfuzzer | -l)
                bazel build --config=fuzzing $FUZZING_TARGET
                ;;
            --afl | -a)
                bazel build --config=afl $FUZZING_TARGET
                ;;
        esac

        FUZZING_BINARY="$WORKSPACE/$(bazel cquery --config=fuzzing --output=files $FUZZING_TARGET)"

        case $1 in
            --testcase | -t)
                LLVM_PROFILE_FILE="fuzzing.profraw" $FUZZING_BINARY $TEST_INPUT
                llvm-profdata-17 merge -sparse fuzzing.profraw -o fuzzing.profdata
                rm fuzzing.profraw
                ;;
            --corpus | -c)
                mkdir -p profdata
                touch profraw_list.txt

                for FILE in "$TEST_INPUT"/*; do
                    FILENAME=$(basename "$FILE" | sha256sum | head -c 40)
                    PROFILE_FILE="profdata/$FILENAME.profraw"
                    LLVM_PROFILE_FILE=$PROFILE_FILE $FUZZING_BINARY $FILE
                    echo "$PWD/$PROFILE_FILE" >>profraw_list.txt
                done
                llvm-profdata-17 merge -f profraw_list.txt -o fuzzing.profdata
                rm -rf profdata/
                rm profraw_list.txt
                ;;
        esac
        ;;
esac

# rustfilt builds over rustc-demangle
cargo install rustfilt
# Source based filtering is possible with llvm-cov-17
llvm-cov-17 export --format=lcov -Xdemangler=rustfilt $FUZZING_BINARY -instr-profile=fuzzing.profdata >lcov_trace
# Change output directory from genhtml if needed
genhtml --ignore-errors source --output genhtml lcov_trace

# Cleanup
rm fuzzing.profdata
rm lcov_trace
