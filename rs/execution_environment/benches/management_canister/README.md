# Management Canister Benchmarks

This benchmark is intended to measure time spent on management_canister calls, eg `create_canister`, `install_code`, etc.

## How to run

- all benches:
    ```shell
    $ bazel run //rs/execution_environment:management_canister_bench
    ```
- skip benchmarks whose names do not contain `<FILTER>`:
    ```shell
    $ bazel run //rs/execution_environment:management_canister_bench -- <FILTER>

    # Eg. run only `create_canisters`
    $ bazel run //rs/execution_environment:management_canister_bench -- create_canisters
    ```
- help
    ```shell
    $ bazel run //rs/execution_environment:management_canister_bench -- -h
    ```
