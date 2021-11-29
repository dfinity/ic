# Run to benchmark the Internet Computer

```
cargo run --bin ic-workload-generator --release -- -u -n 1 'http://localhost:8080'
```

It will then execute `query()` calls, `update()` calls, or a mix of both depending on the `--method` specified. It will issue those requests from `-c`
clients concurrently. Each of these clients will execute `n/c` batches of work. Each batch of work has `-b` messages,
which are executed in parallel.

Generally, see `--help` for a description of available commands.

Originally based on rench (https://github.com/kbacha/rench)

# Summary status counts
- 200: all good (query), great success
- 202: all good (update), great success
- 0: request not submitted
- 11: update send failed
- 33: update request status rejected
- 44: timed out before update request status rejected or replied

# Setup

 - Make sure you have enough open files supported by our OS, on Ubuntu, do something like: `ulimit -n 10240`

# Workloads
- Counter Canister (`--method=QueryCounter` or `--method=UpdateCounter`)
  - Needs to expose `read` and `write` methods
- StateSync Canister (`--method=StateSyncA`)
  - Needs to expose `change_state`, `expand_state`, and `read_state`
- CowSafety Canister (`--method=CowSafetyA`)
  - Needs to expose `init_array`, `query_and_update`, and `compute_sum`
- Custom workload (`--method=Query` or `--method=Update`)
  - The name of the canister method to call should be given using `--canister-method-name=<method name>`.
  - The custom arguments for the canister method can be provided in `--payload=<payload string>` as string.

# Limitations

 - The workload generator only installs a single canister per invocation.
 - Update calls on a canister are executed sequentially one update at a time.
 - The current implementation starts checking the update request status 2s after submission and stops checking the update request status after 60 s (IC MAX TTL is currently 5min) to limit the number of status queries per request, could/should be turned into a command line argument.
