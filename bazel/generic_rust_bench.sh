#!/usr/bin/env bash

set -euo pipefail

# criterion supports specifying a "home" where it places its benchmark result tree.
# at the time of writin, our bazel version (.bazelversion) is outdated and sh_binary
# does not support `env_inherit` so add (or rather intercept) a new CLI argument
# `--criterion-home` which we convert into `CRITERION_HOME`, which is read by
# criterion.rs.
#
# https://github.com/criterion-rs/criterion.rs/blob/950c3b727a09d10067ea686e2ac6f1f23569168f/src/lib.rs#L142-L142

# store passthru args
args=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --criterion-home)
            shift
            export CRITERION_HOME="$1"
            ;;
        *)
            # passthru
            args+=("$1")
            shift
            ;;
    esac
done

# When Cargo runs benchmarks, it passes the --bench or --test command-line arguments to
# the benchmark executables. Criterion.rs looks for these arguments and tries to either
# run benchmarks or run in test mode. In particular, when you run cargo test --benches
# (run tests, including testing benchmarks) Cargo does not pass either of these
# arguments. This is perhaps strange, since cargo bench --test passes both --bench and
# --test. In any case, Criterion.rs benchmarks run in test mode when --bench is not
# present, or when --bench and --test are both present.
#
# https://bheisler.github.io/criterion.rs/book/faq.html#when-i-run-benchmark-executables-directly-without-using-cargo-they-just-print-success-why
CMD="${BAZEL_DEFS_BENCH_PREFIX}${BAZEL_DEFS_BENCH_BIN} --bench ${args[@]}"

echo "running ${CMD}"
${CMD}
