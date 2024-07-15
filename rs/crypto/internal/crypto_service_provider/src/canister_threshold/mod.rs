//! Canister threshold signatures.
//!
//! The code in this file mediates between the external API, the CSP state
//! including the secret key store and random number generator, and the
//! stateless crypto lib.

#[cfg(test)]
mod tests;

use ic_crypto_internal_types::scope::{ConstScope, Scope};

pub const IDKG_MEGA_SCOPE: Scope = Scope::Const(ConstScope::IDkgMEGaEncryptionKeys);
pub const IDKG_THRESHOLD_KEYS_SCOPE: Scope = Scope::Const(ConstScope::IDkgThresholdKeys);
