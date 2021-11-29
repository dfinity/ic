# vim: set ft=bash

hydra_build_products=$out/nix-support/hydra-build-products
mkdir -p $(dirname "$hydra_build_products")

bench_dirs=()
while IFS= read -r bench_dir; do
    echo "Found benchmark directory '$bench_dir'"
    bench_dirs+=("$bench_dir")
done < <(find -L "$benchmark_results/target" -type d -path '*/new')

manifests_dir="$out/manifests" && mkdir -p $manifests_dir

for bench_dir in "${bench_dirs[@]}"; do
    echo "Reading benchmark directory '$bench_dir'"

    benchmark_file="$bench_dir/benchmark.json" && echo "benchmark.json: $benchmark_file"
    if ! [[ -f $benchmark_file ]]; then
        echo "No benchmark file in $bench_dir ($benchmark_file), skipping"
        continue
    fi

    bench_name=$(jq -cMr '.title' <"$benchmark_file")
    # benchmark names can contain all kind of symbols which are not very
    # path-friendly. We replace `<` and `>` with `lt` and `gt` respectively, and
    # then replace all non-alphanum chars with `_`.
    bench_name_sanitized=${bench_name//</lt}
    bench_name_sanitized=${bench_name_sanitized//>/gt}
    bench_name_sanitized=${bench_name_sanitized//[^a-zA-Z0-9]/_}
    bench_manifest="$manifests_dir/$bench_name_sanitized.json"
    if [ -f "$bench_manifest" ]; then
        echo "Benchmark $bench_name_sanitized already exists"
        exit 1
    fi

    report_dir="$(dirname "$bench_dir")/report"

    if [ -d "$report_dir" ]; then
        echo "Found report directory $report_dir ($bench_name_sanitized)"
        echo "report $bench_name_sanitized \"$report_dir\" index.html" >>$hydra_build_products
    fi

    estimates_file="$bench_dir/estimates.json" && echo "estimates.json: $estimates_file"
    if ! [[ -f $estimates_file ]]; then
        echo "No estimates file in $bench_dir ($estimates_file), skipping"
        continue
    fi

    echo '{}' \
        | jq -cMr \
            --slurpfile benchmark "$benchmark_file" \
            --slurpfile estimates "$estimates_file" \
            --arg system "$system" \
            --arg timestamp "$(<"$benchmark_results/timestamp")" \
            --arg rev "$rev" \
            --arg revCount "$revCount" \
            ' .benchmark = $benchmark[] |
        .estimates = $estimates[] |
        .package="replica-benchmarks" |
        .system=$system |
        .timestamp=$timestamp |
        .rev=$rev |
        .revCount=$revCount
      ' >"$bench_manifest"

    echo "doc ${bench_name_sanitized}_json \"$bench_manifest\"" >>$hydra_build_products
done
