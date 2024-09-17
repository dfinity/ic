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

pub mod bitcoin;
pub mod ecdsa;
pub mod http_request;
pub mod main;
pub mod provisional;
pub mod schnorr;
