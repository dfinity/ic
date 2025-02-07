use ed25519::EdwardsCurve;
use p256::Prime256;

use crate::RecoveryError;

use super::Result;

pub mod ed25519;
pub mod p256;

pub trait Verifier {
    fn verify_payload(&self, payload: &[u8], signature: &[u8]) -> Result<()>;

    fn to_public_key_der(&self) -> Result<Vec<u8>>;
}
pub trait Signer: Verifier + Send + Sync {
    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

pub fn verify_payload_naive(public_key_der: &[u8], payload: &[u8], signature: &[u8]) -> Result<()> {
    match EdwardsCurve::from_public_key_der(public_key_der) {
        Ok(verifier) => return verify_payload_naive_inner(verifier, payload, signature),
        _ => {}
    }

    match Prime256::from_public_key_der(public_key_der) {
        Ok(verifier) => return verify_payload_naive_inner(verifier, payload, signature),
        _ => {}
    }

    Err(RecoveryError::InvalidPubKey(
        "Couldn't decode public key der with any known algorithm".to_string(),
    ))
}

fn verify_payload_naive_inner(
    verifier: impl Verifier,
    payload: &[u8],
    signature: &[u8],
) -> Result<()> {
    verifier.verify_payload(payload, signature)
}
