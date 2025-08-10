# Management Canister Benchmarks

This benchmark is intended to measure time spent on management_canister calls, eg `create_canister`, `install_code`, etc.

## How to run

### Bash Script

```shell
$ rs/execution_environment/benches/management_canister/run_benchmarks.sh
```

### Bazel

- all benches:
    ```shell
    $ bazel run //rs/execution_environment:management_canister_bench -- --sample-size 20
    ```
- skip benchmarks whose names do not contain `<FILTER>`:
    ```shell
    $ bazel run //rs/execution_environment:management_canister_bench -- --sample-size 20 <FILTER>

    # Eg. run only `create_canisters`
    $ bazel run //rs/execution_environment:management_canister_bench -- --sample-size 20 create_canisters
    ```
- help
    ```shell
    $ bazel run //rs/execution_environment:management_canister_bench -- -h
    ```

## HTML Report

HTML report can be found at

```shell
$ ls bazel-bin/rs/execution_environment/management_canister_bench.runfiles/ic/target/criterion/report/index.html
```

You can download reports from a remote machine with

```shell
$ scp -r <USER>@zh1-spm22.zh1.dfinity.network:/home/<USER>/<PATH>/ic/bazel-bin/rs/execution_environment/management_canister_bench.runfiles/ic/target/criterion ~/Downloads/criterion
```
