#!/usr/bin/env bash
# A utility script to build all fuzzers on the IC in a single directory.
# TODO(PSEC-998) - Precursor to a scheduled CI pipeline which will upload these to Clusterfuzz via gsutil
set -euo pipefail

case $1 in
    -h | --help)
        cat <<EOF >&2
        usage:
            $0 --bin path/to/dir/   # builds all fuzzing binaries in the given directory.           
            $0 --zip path/to/dir/   # builds and zips' all binaries in given directory. Includes a version.txt file with sha256sum.
EOF
        exit 0
        ;;
    --bin | --zip)
        if [ -z "${2-}" ]; then
            echo "No directory provided. Using fuzzer_build"
            BUILD_DIR="fuzzer_build"
        else
            echo "Using $2 for building"
            BUILD_DIR=$2
        fi
        # ui_event_filters to suppress WARNING: info command does not support starlark options
        WORKSPACE=$(bazel info workspace --ui_event_filters=-WARNING,-INFO 2>/dev/null)
        mkdir -p $BUILD_DIR
        cd $BUILD_DIR
        CURRENT_TIME=$(date '+%Y%m%d%H%M')

        # libfuzzer based fuzzers
        CLUSTERFUZZ_ZIP_PREFIX="libfuzzer_asan_linux"
        LIST_OF_FUZZERS=$(bazel query 'attr(tags, "libfuzzer", //rs/...)')

        for FUZZER in $LIST_OF_FUZZERS; do
            bazel build --config=lint --config=fuzzing $FUZZER
            SOURCE_BINARY="$WORKSPACE/$(bazel cquery --config=fuzzing --output=files $FUZZER)"
            if [ $1 == "--zip" ]; then # zip branch
                SOURCE_BASENAME=$(basename $SOURCE_BINARY)
                zip -j "${CLUSTERFUZZ_ZIP_PREFIX}_${SOURCE_BASENAME}-${CURRENT_TIME}.zip" $SOURCE_BINARY
                # check if we have a corpus generator
                CORPUS_TARGET=$(bazel query 'filter(".*'${SOURCE_BASENAME}'_seed_corpus_generation", kind("rust_binary", //rs/...) union kind("sh_binary", //rs/...) )' | head -n 1)
                if [ ! -z $CORPUS_TARGET ]; then
                    # build new corpus and append to the zip
                    CORPUS_DIR="${SOURCE_BASENAME}_seed_corpus"
                    mkdir $CORPUS_DIR
                    bazel run $CORPUS_TARGET -- "$(pwd)"/$CORPUS_DIR
                    zip -rj "${CORPUS_DIR}.zip" $CORPUS_DIR
                    zip -ru "${CLUSTERFUZZ_ZIP_PREFIX}_${SOURCE_BASENAME}-${CURRENT_TIME}.zip" "${CORPUS_DIR}.zip"
                    rm -r $CORPUS_DIR
                    rm "${CORPUS_DIR}.zip"
                fi
            else # bin branch
                cp -p $SOURCE_BINARY .
            fi
        done

        # AFL based fuzzers
        AFL_ZIP_PREFIX="afl_asan_linux"
        LIST_OF_FUZZERS=$(bazel query 'attr(tags, "afl", //rs/...)')
        # Add a dummy seed corpus file for AFL
        echo "A dummy corpus file to make AFL work" >seed_corpus.txt
        for FUZZER in $LIST_OF_FUZZERS; do
            bazel build --config=lint --config=afl $FUZZER
            SOURCE_BINARY="$WORKSPACE/$(bazel cquery --config=fuzzing --output=files $FUZZER)"
            if [ $1 == "--zip" ]; then # zip branch
                SOURCE_BASENAME=$(basename $SOURCE_BINARY)
                zip -j "${SOURCE_BASENAME}_seed_corpus.zip" seed_corpus.txt
                zip -j "${AFL_ZIP_PREFIX}_${SOURCE_BASENAME}-${CURRENT_TIME}.zip" $SOURCE_BINARY /afl/afl-fuzz /afl/afl-showmap
                zip -ru "${AFL_ZIP_PREFIX}_${SOURCE_BASENAME}-${CURRENT_TIME}.zip" "${SOURCE_BASENAME}_seed_corpus.zip"
                rm -r "${SOURCE_BASENAME}_seed_corpus.zip"
            else # bin branch
                cp -p $SOURCE_BINARY .
            fi
        done
        rm seed_corpus.txt
        ;;
esac
