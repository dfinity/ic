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
            echo "No directory provided. Using fuzzer_build/"
            BUILD_DIR="fuzzer_build/"
        else
            echo "Using $2 for building"
            BUILD_DIR=$2
        fi
        CLUSTERFUZZ_ZIP_PREFIX="libfuzzer_linux"
        LIST_OF_FUZZERS=$(bazel query 'attr(tags, "fuzz_test", //rs/...)')
        # ui_event_filters to suppress WARNING: info command does not support starlark options
        WORKSPACE=$(bazel info workspace --ui_event_filters=-WARNING,-INFO 2>/dev/null)
        mkdir -p $BUILD_DIR
        cd $BUILD_DIR
        for FUZZER in $LIST_OF_FUZZERS; do
            bazel build --config=fuzzing $FUZZER
            SOURCE_BINARY="$WORKSPACE/$(bazel cquery --config=fuzzing --output=files $FUZZER)"
            if [ $1 == "--bin" ]; then
                cp -p $SOURCE_BINARY .
            else # zip branch
                SOURCE_BASENAME=$(basename $SOURCE_BINARY)
                # gzip -c $SOURCE_BINARY > "${CLUSTERFUZZ_ZIP_PREFIX}_${SOURCE_BASENAME}.gz"
                zip -j "${CLUSTERFUZZ_ZIP_PREFIX}_${SOURCE_BASENAME}.zip" $SOURCE_BINARY
                echo $(sha256sum "${CLUSTERFUZZ_ZIP_PREFIX}_${SOURCE_BASENAME}.zip") >>version.txt
            fi
        done
        ;;
esac
