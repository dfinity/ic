//! (deprecated) Key share encryption for interactive distributed key
//! generation.

use crate::dkg::secp256k1::types::{EncryptedShare, EphemeralPublicKeyBytes};
use crate::types::SecretKey as ThresholdSecretKey;
use ff::Field;
use ic_crypto_internal_bls12381_common::hash_to_fr;
use ic_crypto_internal_types::context::{Context, DomainSeparationContext};
use ic_crypto_sha256::Sha256;
use ic_types::IDkgId;

#[cfg(test)]
mod tests;

const DOMAIN_SEPERATOR_DH_ENCRYPT: &str = "encryption key";
type KeyEncryptionKey = ThresholdSecretKey;

/// Computes the key encryption key added/subtracted to shares during
/// encryption/decryption.
///
/// One node (the dealer) generates a secret key (the share) for another (the
/// receiver).  In order to transfer this key securely, it is encrypted and
/// subsequently decrypted with a key encryption key derived here.
///
/// # Arguments
/// * `dkg_id` - the DKG this Diffie Hellman is to be used for.
/// * `dealer_public_key` - the public key of the node issuing the key share.
/// * `receiver_public_key` - the public key of the node receiving the key
///   share.
/// * `diffie_hellman` - the output of the Diffie Hellman; as this is computed
///   in various ways it is up to the caller to provide it.
/// # Panics
/// This method is not expected to panic.
pub fn key_encryption_key<
    PK1: Into<EphemeralPublicKeyBytes>,
    PK2: Into<EphemeralPublicKeyBytes>,
    PK3: Into<EphemeralPublicKeyBytes>,
>(
    dkg_id: IDkgId,
    dealer_public_key: PK1,
    receiver_public_key: PK2,
    diffie_hellman: PK3,
) -> KeyEncryptionKey {
    let dealer_public_key: EphemeralPublicKeyBytes = dealer_public_key.into();
    let receiver_public_key: EphemeralPublicKeyBytes = receiver_public_key.into();
    let diffie_hellman: EphemeralPublicKeyBytes = diffie_hellman.into();
    let mut hash = Sha256::new();
    hash.write(DomainSeparationContext::new(DOMAIN_SEPERATOR_DH_ENCRYPT).as_bytes());
    hash.write(&serde_cbor::to_vec(&dkg_id).expect("Failed to serialize to CBOR"));
    hash.write(&dealer_public_key.0);
    hash.write(&receiver_public_key.0);
    hash.write(&diffie_hellman.0);
    hash_to_fr(hash)
}

/// Encrypts a threshold key share
///
/// # Arguments
/// * `dkg_id` - the DKG this Diffie Hellman is to be used for.
/// * `dealer_public_key` - the public key of the node issuing the key share.
/// * `receiver_public_key` - the public key of the node receiving the key
///   share.
/// * `diffie_hellman` - the output of the Diffie Hellman; this may be computed
///   from the dealer secret key and the receiver public key.
/// * `secret_share` - the key share to be encrypted.
/// # Panics
/// This method is not expected to panic.
pub(super) fn encrypt_share<
    PK1: Into<EphemeralPublicKeyBytes>,
    PK2: Into<EphemeralPublicKeyBytes>,
    PK3: Into<EphemeralPublicKeyBytes>,
>(
    dkg_id: IDkgId,
    dealer_public_key: PK1,
    receiver_public_key: PK2,
    diffie_hellman: PK3,
    secret_share: ThresholdSecretKey,
) -> EncryptedShare {
    let mut ans = key_encryption_key(
        dkg_id,
        dealer_public_key,
        receiver_public_key,
        diffie_hellman,
    );
    ans.add_assign(&secret_share);
    ans
}

/// Decrypts a threshold key share
///
/// # Arguments
/// * `dkg_id` - the DKG this Diffie Hellman is to be used for.
/// * `dealer_public_key` - the public key of the node issuing the key share.
/// * `receiver_public_key` - the public key of the node receiving the key
///   share.
/// * `diffie_hellman` - the output of the Diffie Hellman; this may be computed
///   from the receiver secret key and the dealer public key.
/// * `encrypt_share` - the key share to be decrypted.
/// # Panics
/// This method is not expected to panic.
pub(super) fn decrypt_share<
    PK1: Into<EphemeralPublicKeyBytes>,
    PK2: Into<EphemeralPublicKeyBytes>,
    PK3: Into<EphemeralPublicKeyBytes>,
>(
    dkg_id: IDkgId,
    dealer_public_key: PK1,
    receiver_public_key: PK2,
    diffie_hellman: PK3,
    mut encrypted_share: EncryptedShare,
) -> ThresholdSecretKey {
    encrypted_share.sub_assign(&key_encryption_key(
        dkg_id,
        dealer_public_key,
        receiver_public_key,
        diffie_hellman,
    ));
    encrypted_share
}
