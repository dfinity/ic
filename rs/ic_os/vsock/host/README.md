# vsock_host

HostOS-side entry point for the vsock server.

## How it works
- `src/main.rs` is intentionally tiny and just calls `vsock_lib::run_server()`.
- All protocol parsing, command dispatch, and connection handling live in
  `vsock_lib`.

If you need to change server behavior, start in `../vsock_lib/` rather than in
this crate.
