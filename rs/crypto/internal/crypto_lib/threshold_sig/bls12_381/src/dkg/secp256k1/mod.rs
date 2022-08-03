//! (deprecated) Distributed Key Generation using secp256k1.
//!
//! Modules are used in this order:
//! * ephemeral_key for key generation
//! * dealing (uses dh)
//! * response (uses complaint)
//! * transcript

pub mod types;
