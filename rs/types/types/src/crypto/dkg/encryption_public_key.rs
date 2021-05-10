use super::*;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;

/// An encryption public key for interactive DKG.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EncryptionPublicKey {
    internal: CspEncryptionPublicKey,
}

impl Default for EncryptionPublicKey {
    // TODO (CRP-328)
    fn default() -> Self {
        EncryptionPublicKey::from(&CspEncryptionPublicKey::default())
    }
}

impl From<&CspEncryptionPublicKey> for EncryptionPublicKey {
    fn from(csp_enc_pk: &CspEncryptionPublicKey) -> Self {
        EncryptionPublicKey {
            internal: *csp_enc_pk,
        }
    }
}

impl From<&EncryptionPublicKey> for CspEncryptionPublicKey {
    fn from(enc_pk: &EncryptionPublicKey) -> Self {
        enc_pk.internal
    }
}
