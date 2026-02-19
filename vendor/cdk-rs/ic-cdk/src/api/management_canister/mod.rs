//! Functions and types for calling [the IC management canister][1].
//!
//! This module is a direct translation from the [interface description][2].
//!
//! The functions and types defined in this module serves these purposes:
//! * Make it easy to construct correct request data.
//! * Handle the response ergonomically.
//! * For those calls require cycles payments, the cycles amount is an explicit argument.
//!
//! [1]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister
//! [2]: https://internetcomputer.org/assets/files/ic-a45d11feb0ba0494055083f9d2d21ddf.did
#![allow(deprecated)]
#[deprecated(
    since = "0.18.0",
    note = "The `api::management_canister::bitcoin` module is deprecated. Please use the `bitcoin_canister` module at the crate root."
)]
pub mod bitcoin;
#[deprecated(
    since = "0.18.0",
    note = "The `api::management_canister::ecdsa` module is deprecated. Please use the `management_canister` module at the crate root."
)]
pub mod ecdsa;
#[deprecated(
    since = "0.18.0",
    note = "The `api::management_canister::http_request` module is deprecated. Please use the `management_canister` module at the crate root."
)]
pub mod http_request;
#[deprecated(
    since = "0.18.0",
    note = "The `api::management_canister::main` module is deprecated. Please use the `management_canister` module at the crate root."
)]
pub mod main;
#[deprecated(
    since = "0.18.0",
    note = "The `api::management_canister::provisional` module is deprecated. Please use the `management_canister` module at the crate root."
)]
pub mod provisional;
#[deprecated(
    since = "0.18.0",
    note = "The `api::management_canister::schnorr` module is deprecated. Please use the `management_canister` module at the crate root."
)]
pub mod schnorr;
