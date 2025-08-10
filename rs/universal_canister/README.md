Universal Canister
==================

The implementation of the universal canister is in `/impl`, while the library that
tests use to interface with the universal canister is in `/lib`.

Note that the universal canister's implementation is temporarily using its `Cargo.lock` file
and is excluded from being built in the top-level workspace. In the future, it will be
integrated into the top-level workspace and its `Cargo.lock` will be merged.
