use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_interfaces::crypto::Crypto;
use ic_interfaces_registry::RegistryClient;
use std::sync::Arc;

/// A crypto component that should only be used for verification.
pub trait CryptoComponentForVerificationOnly: Crypto {}

// Blanket implementation of `CryptoComponentForVerificationOnly` for all types
// that fulfill the requirements.
impl<T> CryptoComponentForVerificationOnly for T where T: Crypto {}

/// Returns a crypto component that should only be used for verification.
///
/// All keys are newly generated, and the secret parts are stored in a
/// temporary directory that is deleted automatically when the crypto
/// component goes out of scope. This is is the reason why the returned
/// crypto component should only be used for public key operations, i.e.,
/// for verification only.
///
/// The returned crypto component is _hidden_ behind a trait, where the
/// trait's name acts as reminder that it should be used for verification
/// only.
pub fn new(registry_client: Arc<dyn RegistryClient>) -> impl CryptoComponentForVerificationOnly {
    TempCryptoComponent::builder()
        .with_registry(registry_client)
        .with_keys(NodeKeysToGenerate::all())
        .build()
}
