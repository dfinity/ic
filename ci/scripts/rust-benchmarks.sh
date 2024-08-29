#!/usr/bin/env bash
set -eEuo pipefail

TARGET_LIST=$(bazel query "attr(tags, 'rust_bench', ${TARGETS:-'//rs/...'})")
for TARGET in $TARGET_LIST; do
    export BAZEL_TARGETS="$TARGET"
    time ./gitlab-ci/src/bazel-ci/main.sh
done
find -L ./bazel-out -name 'benchmark.json'

set -x
while IFS= read -r bench_dir; do
    echo '{}' | jq -cMr \
        --slurpfile benchmark "$bench_dir/benchmark.json" \
        --slurpfile estimates "$bench_dir/estimates.json" \
        --arg system x86_64-linux \
        --arg timestamp "$(date --utc --iso-8601=seconds)" \
        --arg rev "$CI_COMMIT_SHA" \
        '.benchmark = $benchmark[] |
    .estimates = $estimates[] |
    .package = "replica-benchmarks" |
    .system = $system |
    .timestamp = $timestamp |
    .rev = $rev |
    .revCount = 1' \
        >report.json
    curl --fail --retry 2 -sS -o /dev/null -X POST -H 'Content-Type: application/json' --data @report.json \
        "https://elasticsearch.testnet.dfinity.network/ci-performance-test/_doc"
done < <(find -L ./bazel-out -type d -path '*/new')
