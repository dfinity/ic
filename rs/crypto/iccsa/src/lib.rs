//! ICCSA (Internet Computer Canister Signature Algorithm) aka Canister Signatures.
//!
//! This crate re-exports the internal implementation of ICCSA for the use outside `rs/crypto`.
//! For the documentation, refer to the
//! [IC interface spec](https://internetcomputer.org/docs/current/references/ic-interface-spec#canister-signatures)
//! and the exported implementation.

pub use ic_crypto_internal_basic_sig_iccsa::*;
