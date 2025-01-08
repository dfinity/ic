Execution Benchmarks
====================

Quick Start
-----------

1. To run all benchmarks and compare them to the committed baseline:

    ```sh
    ./rs/execution_environment/benches/run-all-benchmarks.sh | tee summary.txt
    ```

    The summary will be generated in the `summary.txt` file.

2. To update the baseline:

    ```sh
    cp *.min rs/execution_environment/benches/baseline
    git add rs/execution_environment/benches/baseline/*
    git commit -m "Update benches baseline"
    ```

Adding a New Benchmark
----------------------

1. Create a new benchmark and test it with `bazel run ...`.

2. To integrate the new benchmark into the CI pipeline:

    ```Starlark
    rust_ic_bench(
        name = "my_new_bench",
        with_test = True,
        [...]
    )
    ```

    Note, a single benchmark iteration should run in a reasonable amount of time:

    ```sh
    bazel run //rs/execution_environment:my_new_bench -- --test
    ```

3. To include the new benchmark in the comparison:

   Edit script: `rs/execution_environment/benches/run-all-benchmarks.sh`
