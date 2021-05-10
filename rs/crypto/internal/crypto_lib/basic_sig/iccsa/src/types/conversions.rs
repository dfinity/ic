use crate::types::{PublicKey, PublicKeyBytes};
use ic_types::CanisterId;
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

/// Tries to construct an ICCSA public key according to the interface
/// specification, assuming that the DER-wrapping was already removed.
///
/// In particular, parses the blob |signing_canister_id| ·
/// signing_canister_id · seed, where |signing_canister_id| is the one-byte
/// encoding of the the length of the signing_canister_id and · denotes blob
/// concatenation.
impl TryFrom<&PublicKeyBytes> for PublicKey {
    type Error = PublicKeyFromBytesError;

    fn try_from(pubkey_bytes: &PublicKeyBytes) -> Result<Self, Self::Error> {
        let canister_id_len = match pubkey_bytes.0.get(0) {
            Some(length_byte) => usize::from(*length_byte),
            None => return Err(PublicKeyFromBytesError::MissingCanisterIdLengthByte),
        };
        if pubkey_bytes.0.len() < (1 + canister_id_len) {
            return Err(PublicKeyFromBytesError::Malformed);
        }
        let canister_id_raw = &pubkey_bytes.0[1..=canister_id_len];
        let seed = &pubkey_bytes.0[canister_id_len + 1..];

        let canister_id = CanisterId::try_from(canister_id_raw)
            .map_err(|_| PublicKeyFromBytesError::InvalidCanisterId)?;
        Ok(PublicKey {
            signing_canister_id: canister_id,
            seed: seed.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKeyFromBytesError {
    Malformed,
    MissingCanisterIdLengthByte,
    InvalidCanisterId,
}
