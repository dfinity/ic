ic-dummy-getrandom-for-wasm
=============================

The `rand` crate is widely used in the Rust ecosystem. The `rand` crate in turn
relies on `getrandom` to acquire cryptographic seed material. For policy
reasons, `getrandom` refuses to compile on the `wasm32-unknown-unknown` target
used by the Internet Computer. This prevents using `rand` without workarounds.

This crate implements such a workaround; on `wasm32-unknown-unknown` target, it
registers a custom getrandom implementation which just returns an error at
runtime. On any other target, it does nothing.

