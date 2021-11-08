//! Reusable test code

use crate::{
    crypto as multi_crypto,
    types::{CombinedSignature, IndividualSignature, PublicKey, SecretKey},
};
use bls12_381::G1Projective;

pub fn single_point_signature_verifies(
    secret_key: SecretKey,
    public_key: PublicKey,
    point: G1Projective,
) {
    let signature = multi_crypto::sign_point(point, secret_key);
    assert!(multi_crypto::verify_point(point, signature, public_key));
}
pub fn individual_multi_signature_contribution_verifies(
    secret_key: SecretKey,
    public_key: PublicKey,
    message: &[u8],
) {
    let signature = multi_crypto::sign_message(&message, secret_key);
    assert!(multi_crypto::verify_individual_message_signature(
        message, signature, public_key
    ));
}

pub fn multi_signature_verifies(keys: &[(SecretKey, PublicKey)], message: &[u8]) {
    let signatures: Vec<IndividualSignature> = keys
        .iter()
        .map(|(secret_key, _)| multi_crypto::sign_message(message, *secret_key))
        .collect();
    let signature: CombinedSignature = multi_crypto::combine_signatures(&signatures);
    let public_keys: Vec<PublicKey> = keys
        .iter()
        .map(|(_, public_key)| public_key)
        .copied()
        .collect();
    assert!(multi_crypto::verify_combined_message_signature(
        message,
        signature,
        &public_keys
    ));
}
