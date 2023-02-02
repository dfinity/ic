# Transport benchmarks

## How to compare against master

Before doing any code changes or on the master branch create a reference baseline.

```
bazel run //rs/transport:transport_bench -- --save-baseline master
```

to compare against the master baseline run

```
bazel run //rs/transport:transport_bench -- --baseline master
```