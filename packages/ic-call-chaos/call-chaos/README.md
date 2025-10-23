# IC Call Chaos

A library for testing and simulating inter-canister call failures on the Internet Computer.

The intended use case is to conditionally import the Call struct from this crate instead from the Rust CDK while testing your code. Policies can then be set to control which calls to fail.

See the example usage in [tests](https://github.com/oggy-dfin/ic_call_utils/tree/master/call_chaos/tests)

Use `cargo release` to release new versions
