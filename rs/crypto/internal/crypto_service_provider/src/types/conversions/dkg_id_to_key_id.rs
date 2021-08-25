//! Compute a key identifier for a DKG id

use ic_crypto_sha256::{Context, DomainSeparationContext};
use ic_types::crypto::KeyId;
use ic_types::IDkgId;

#[cfg(test)]
mod tests;

/// Compute a key identifier for a DKG id
// This conversion is currently in a separate module since it cannot be
// implemented using the `From` trait in the types crate. The reason for this is
// that the types crate has no dependency on crypto.
// TODO (DFN-1381): This can be fixed once the KeyId is moved from types to
// crypto.
// TODO (DFN-1460): Clarify requirements regarding domain separation, maybe move
// this conversion to CSP layer
pub fn dkg_id_to_key_id(dkg_id: &IDkgId) -> KeyId {
    let mut hash = openssl::sha::Sha256::new();
    hash.update(DomainSeparationContext::new("dkg_id_domain").as_bytes());
    hash.update(&serde_cbor::to_vec(&dkg_id).expect("Could not serialise DkgId"));
    let digest = hash.finish();
    KeyId(digest)
}
