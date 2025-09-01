#!/usr/bin/env bash

set -euo pipefail

# When Cargo runs benchmarks, it passes the --bench or --test command-line arguments to
# the benchmark executables. Criterion.rs looks for these arguments and tries to either
# run benchmarks or run in test mode. In particular, when you run cargo test --benches
# (run tests, including testing benchmarks) Cargo does not pass either of these
# arguments. This is perhaps strange, since cargo bench --test passes both --bench and
# --test. In any case, Criterion.rs benchmarks run in test mode when --bench is not
# present, or when --bench and --test are both present.
#
# https://bheisler.github.io/criterion.rs/book/faq.html#when-i-run-benchmark-executables-directly-without-using-cargo-they-just-print-success-why
CMD="${BAZEL_DEFS_BENCH_PREFIX}${BAZEL_DEFS_BENCH_BIN} --bench $@"

echo "running ${CMD}"
${CMD}
