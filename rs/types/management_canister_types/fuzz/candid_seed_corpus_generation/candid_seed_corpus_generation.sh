#!/usr/bin/env bash

set -x

# IC method from the interface spec
IC_METHOD=$1

# Directory to generate the corpus
CORPUS_DIR=$2

mkdir -p $CORPUS_DIR

for i in {1..50}; do
    echo "Generating ${CORPUS_DIR}/${IC_METHOD}_${i}.txt"
    $DIDC_PATH encode "$($DIDC_PATH random --defs $IC_SPEC --method $IC_METHOD --lang did)" --format hex --defs $IC_SPEC --method $IC_METHOD | xxd -r -p >"${CORPUS_DIR}/${IC_METHOD}_${i}.txt"
done
