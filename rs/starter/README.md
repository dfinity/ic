# ic-starter

The ic-starter provides a minimal functioning environment for a single replica to be used with the SDK.

Minimal example use, from the `rs/` directory:

```
cargo run --bin ic-starter
```

This will:

- compile the replica with the default cargo build options
- start the built replica, listening on port 8080

Run replica in release mode:

```
cargo run --bin ic-starter --release
```

Another more complete example with additional arguments:

```
cargo run --bin ic-starter -- --state-dir=/some/dir \
    --log-level info --metrics-addr 127.0.0.1:18080
```

That:

- starts the replica in debug build
- uses `/some/dir` to store state
- sets the log level to info
- serves metrics at port 18080 instead of dumping them at stdout
