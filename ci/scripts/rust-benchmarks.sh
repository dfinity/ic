#!/usr/bin/env bash
set -euo pipefail

while IFS= read -r tgt; do
    BAZEL_COMMAND=run BAZEL_TARGETS="$tgt" time ./ci/bazel-scripts/main.sh
done < <(bazel query "attr(tags, 'rust_bench', ${TARGETS:-'//rs/...'})")

while IFS= read -r bench_dir; do
    echo "bench dir: $bench_dir"
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
        "https://elasticsearch.ch1-obsdev1.dfinity.network/ci-performance-test/_doc"
done < <(find -L ./bazel-out -type d -path '*/new')
