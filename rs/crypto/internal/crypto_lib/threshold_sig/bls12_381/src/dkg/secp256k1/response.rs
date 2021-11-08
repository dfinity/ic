//! (deprecated) Response creation/verification for interactive distributed key
//! generation.

use super::complaint;
use crate::api::dkg_errors::{
    DkgCreateResponseError, DkgVerifyResponseError, InvalidArgumentError,
};
use crate::dkg::secp256k1::types::{
    CLibComplaintBytes, CLibDealingBytes, CLibResponseBytes, EphemeralPublicKey,
    EphemeralPublicKeyBytes, EphemeralSecretKey, EphemeralSecretKeyBytes,
};
use ic_types::{IDkgId, NodeIndex, Randomness};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;
use std::collections::btree_map::BTreeMap;
use std::convert::TryFrom;

#[cfg(test)]
pub mod tests;

/// Checks whether my share is correct in all dealings and responds with any
/// complaints.
///
/// # Arguments
/// * `seed` - A random seed used to generate complaints.
/// * `receiver_secret_key_bytes` - the current node is the receiver; this is
///   the current node's secret ephemeral key used to decrypt the threshold key
///   share.
/// * `dkg_id` - identifier for the key generation
/// * `verified_dealings` - for each qualified dealer, the dealer's public key
///   and the key share for the current node.
/// * `receiver_index` - each receiver has an index; this is the index for the
///   current node.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// This method MUST return an error if:
/// * one of the keys is malformed.  It is the caller's responsibility to verify
///   that the data is well formed before calling this method.
pub fn create_response(
    seed: Randomness,
    receiver_secret_key_bytes: &EphemeralSecretKeyBytes,
    dkg_id: IDkgId,
    verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    receiver_index: NodeIndex,
) -> Result<CLibResponseBytes, DkgCreateResponseError> {
    let receiver_secret_key = EphemeralSecretKey::try_from(receiver_secret_key_bytes)
        .map_err(DkgCreateResponseError::MalformedSecretKeyError)?;
    let receiver_public_key = EphemeralPublicKey::from(&receiver_secret_key);
    let mut rng = ChaChaRng::from_seed(seed.get());

    let complaints: Result<
        BTreeMap<EphemeralPublicKeyBytes, Option<CLibComplaintBytes>>,
        DkgCreateResponseError,
    > = verified_dealings
        .iter()
        .map(|(dealer_public_key_bytes, dealing)| {
            complaint::complain_maybe(
                &mut rng,
                dkg_id,
                receiver_index,
                &receiver_secret_key,
                &receiver_public_key,
                dealer_public_key_bytes,
                dealing,
            )
            .map(|complaint_maybe| (*dealer_public_key_bytes, complaint_maybe))
        })
        .collect();
    let complaints = complaints?;
    Ok(CLibResponseBytes { complaints })
}

/// Verifies the response against all dealings. This is used before including
/// the response in a block.
///
/// # Arguments
/// * `dkg_id` - identifier for the key generation
/// * `verified_dealings` - for each qualified dealer, their dealing.
/// * `receiver_index` - each receiver has an index; this is the index for the
///   responding receiver.
/// * `receiver_key` - the receiver's public key, used to verify that the
///   receiver's complaints are legitimate.
/// * `response` - the response being verified.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// This method MUST return an error if:
/// * the length of `verified_dealings` is not the same as that of `response`.
/// * a complaint in the response is invalid.
pub fn verify_response(
    dkg_id: IDkgId,
    verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    receiver_index: NodeIndex,
    receiver_public_key_bytes: EphemeralPublicKeyBytes,
    response: &CLibResponseBytes,
) -> Result<(), DkgVerifyResponseError> {
    if verified_dealings.len() != response.complaints.len() {
        return Err(DkgVerifyResponseError::InvalidResponseError(
            InvalidArgumentError {
                message: "CLibDealings don't match responses".to_string(),
            },
        ));
    }
    for (dealer_public_key_bytes, complaint_maybe) in &response.complaints {
        let dealing = verified_dealings
            .get(dealer_public_key_bytes)
            .ok_or_else(|| {
                DkgVerifyResponseError::InvalidResponseError(InvalidArgumentError {
                    message: "Cannot respond to no dealing".to_string(),
                })
            })?;
        if let Some(complaint) = complaint_maybe {
            complaint::verify_complaint(
                dkg_id,
                dealing,
                receiver_index,
                dealer_public_key_bytes,
                &receiver_public_key_bytes,
                complaint,
            )?
        }
    }
    Ok(())
}
