//! This crate exists to work around a problem with `getrandom` 0.3, which is a dependency
//! of `rand` 0.9
//!
//! For the `wasm32-unknown-unknown` target, `getrandom` 0.3 will refuse to compile. This is an
//! intentional policy decision on the part of the getrandom developers. As a consequence, it
//! would not be possible to compile anything which depends on `rand` 0.9 to wasm for use in
//! canister code.
//!
//! Depending on this crate converts the compile time error into a runtime error, by
//! registering a custom `getrandom` implementation which always fails. This matches the
//! behavior of `getrandom` 0.1. For code that is not being compiled to
//! `wasm32-unknown-unknown`, this crate has no effect whatsoever.
//!
//! The reason for placing this function into its own dedicated crate is that it not possible
//! to register more than one getrandom implementation. If more than one custom getrandom
//! implementation existed within the source tree, then a canister which depended on two
//! different crates which included the workaround would fail to build due to the conflict.
//!
//! See the [getrandom
//! documentation](https://docs.rs/getrandom/latest/getrandom/index.html#custom-backend)
//! for more details on custom implementations.

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
/// A getrandom implementation that always fails
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    _dest: *mut u8,
    _len: usize,
) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
