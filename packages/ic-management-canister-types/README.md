# ic-management-canister-types

Types for calling [the IC management canister][1].

This module is a direct translation from its Candid interface description.

[1]: https://docs.internetcomputer.org/references/management-canister/

## Correctness

This crate ensures type definition correctness through the [`candid_equality.rs`](tests/candid_equality.rs) test.

The test defines a dummy Canister covering all Management Canister entry points available for inter-canister calls.

It then asserts the equality of the dummy canister's interface with the specified interface in [`ic.did`](tests/ic.did).

The [`ic.did`](tests/ic.did) is sourced from the [Internet Computer Interface Specification](https://docs.internetcomputer.org/references/management-canister/#candid-interface).

Some methods are excluded (commented out) as follows:
- Bitcoin API: These functionalities are planned to migrate from the Management Canister to the [Bitcoin Canister](https://github.com/dfinity/bitcoin-canister).
