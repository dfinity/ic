# ic-test-utilities-net

Small, `tokio`-only networking helpers for tests.

## `saturated_loopback_listener`

Binds a loopback TCP listener with a minimal backlog (`listen(1)`) and
saturates its accept queue with never-accepted connections. Once the queue is
full the kernel silently drops further SYNs, so any subsequent connect to the
returned address neither completes nor is refused — it hangs until the
connecting side's own timeout fires.

This lets a test exercise a **connect-timeout** code path using only loopback,
so it does **not** require network egress (and can therefore run without the
`requires-network` Bazel tag). A non-routable address such as `10.255.255.1`
only times out when a default route exists to black-hole the packets; without
one the OS returns an immediate "network unreachable" error instead.

```rust
// Keep the guard alive: dropping it frees the port and empties the accept
// queue, after which the address behaves normally again.
let _saturated = ic_test_utilities_net::saturated_loopback_listener().await;
let addr = _saturated.addr();
// Connecting to `addr` now hangs until your timeout fires.
```

Current users: the bitcoin adapter (`ic-btc-adapter`) and the HTTPS-outcalls
adapter (`ic-https-outcalls-adapter`) connect-timeout tests.
