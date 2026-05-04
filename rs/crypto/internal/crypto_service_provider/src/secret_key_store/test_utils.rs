// Note: The mock and temp secret key stores are used in the IDKM.
// Weird compiler errors - can a mock from elsewhere not be used?
// Ok, let's duplicate the mock and see what happens.

use crate::key_id::KeyId;
use crate::types::CspSecretKey;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_secrets_containers::SecretArray;
use rand::{CryptoRng, Rng};

pub fn make_key_id<R: Rng + CryptoRng>(rng: &mut R) -> KeyId {
    KeyId::from(rng.r#gen::<[u8; 32]>())
}

pub fn make_secret_key<R: Rng + CryptoRng>(rng: &mut R) -> CspSecretKey {
    CspSecretKey::Ed25519(ed25519_types::SecretKeyBytes(
        SecretArray::new_and_dont_zeroize_argument(&rng.r#gen()),
    ))
}
