# ic-fstrim-tool

Runs `fstrim` on GuestOS filesystems and exports Prometheus metrics about the
result.

## How it works
- Executes `fstrim` for the configured mount points.
- Detects whether the node is already assigned to a subnet and skips trimming
  the data directory in that case.
- Parses any existing metrics file, updates the relevant gauges/counters, and
  writes the new metrics atomically.

Most of the operational logic is in `src/lib.rs`; `src/main.rs` is the thin CLI
wrapper.
