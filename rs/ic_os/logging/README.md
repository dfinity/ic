# ic_os_logging

Logging utilities for IC-OS binaries.

## What it provides
- `init_logging()` for normal userspace logging.
- `init_kmsg_logging()` for writing log output to `/dev/kmsg` with syslog-style
  priority and identifier prefixes.

## How it works
- `init_logging()` tries to install a `tracing` subscriber backed by journald.
- If journald is unavailable, it falls back to formatted stderr logging.
- `init_kmsg_logging()` writes to `/dev/kmsg` when available and otherwise falls
  back to stderr using the same kmsg-style formatting.
- The kmsg formatter derives the log identifier from `argv[0]`, falling back to
  `ic_os` if needed.

The crate keeps common IC-OS logging setup in one place so binaries can opt into
either the normal journald/stderr path or the kmsg-oriented path with a single
function call.
