//! Canister threshold signatures.
//!
//! The code in this file mediates between the external API, the CSP state
//! including the secret key store and random number generator, and the
//! stateless crypto lib.

#[cfg(test)]
mod tests;

use crate::api::{CspCreateMEGaKeyError, CspIDkgProtocol};
use crate::Csp;
use ic_crypto_internal_threshold_sig_ecdsa::MEGaPublicKey;
use ic_crypto_internal_types::scope::{ConstScope, Scope};
use ic_logger::debug;

pub const IDKG_MEGA_SCOPE: Scope = Scope::Const(ConstScope::IDkgMEGaEncryptionKeys);
pub const IDKG_THRESHOLD_KEYS_SCOPE: Scope = Scope::Const(ConstScope::IDkgThresholdKeys);

/// Interactive distributed key generation client
///
/// Please see the trait definition for full documentation.
impl CspIDkgProtocol for Csp {
    fn idkg_gen_dealing_encryption_key_pair(&self) -> Result<MEGaPublicKey, CspCreateMEGaKeyError> {
        debug!(self.logger; crypto.method_name => "idkg_gen_dealing_encryption_key_pair");

        self.csp_vault.idkg_gen_dealing_encryption_key_pair()
    }
}
