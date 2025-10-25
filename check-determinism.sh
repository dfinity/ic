#!/bin/sh

for i in $(seq 1 10); do
    DATE=$(date +'%Y%m%d-%H%M')
    echo "==> RUN #${i} at ${DATE}"

    bazel test //rs/embedders/... //rs/execution_environment/... \
        --test_output=streamed --test_arg=--nocapture \
        --test_arg=--test-threads=1 --local_test_jobs=1 \
        --nocache_test_results >"determinism-${DATE}.log" 2>&1

    cat determinism-* \
        | tr -s '\0' ' ' \
        | sed -E -e 's/^test ([^ ]*)/TEST:\1\n/g' \
            -e 's/.*XXX_(.*)_ZZZ.*/DUMP:\1\n/g' \
        | rg '^(DUMP:)' \
        | sort | uniq -u
done
