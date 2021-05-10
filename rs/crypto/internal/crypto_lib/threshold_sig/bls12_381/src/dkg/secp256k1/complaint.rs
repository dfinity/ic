//! (deprecated) Make and verify complaints during interactive distributed key
//! generation.

use super::dh;
use crate::api::dkg_errors::{
    DkgCreateResponseError, DkgVerifyResponseError, InvalidArgumentError, MalformedDataError,
    SizeError,
};
use crate::{
    crypto::secret_key_is_consistent,
    dkg::secp256k1::types::{
        CLibComplaint, CLibComplaintBytes, CLibDealingBytes, EncryptedShare, EncryptedShareBytes,
        EphemeralPublicKey, EphemeralPublicKeyBytes, EphemeralSecretKey, EphemeralSecretKeyBytes,
        SECP256K1_PUBLIC_KEY_ONE,
    },
    types::{PublicCoefficients, SecretKey as ThresholdSecretKey},
};
use ic_crypto_internal_types::context::{Context, DomainSeparationContext};
use ic_crypto_sha256::Sha256;
use ic_types::crypto::CryptoError;
use ic_types::{crypto::AlgorithmId, IDkgId, NodeIndex, Randomness};
use rand::{CryptoRng, Rng};
use std::convert::{TryFrom, TryInto};

#[cfg(test)]
mod tests;

const DOMAIN_POK_COMPLAINT: &str = "pok dkg complaint";

/// Complains if the share in a dealing is not on the curve defined by the
/// public coefficients.
///
/// # Arguments
/// * `rng` - a random number generator used to prove that a share is bad.
/// * `dkg_id` - identifier for the key generation
/// * `receiver_index` - index of this receiver in the list of receivers
/// * `receiver_secret_key` - the ephemeral key of this receiver used to decrypt
///   the share.
/// * `receiver_public_key` - the corresponding public key, to avoid recomputing
///   it.
/// * `dealer_public_key_bytes` - the ephemeral public key of the dealer used to
///   decrypt the share.
/// * `dealing` - the dealing being examined.
/// # Panics
/// This method is not expected to panic
/// # Errors
/// * This code MAY not check that the `receiver_public_key` matches the
///   `receiver_secret_key`.  It is the caller's responsibility to ensure that
///   they are correct.
/// * This code MUST return an error if:
///   * an argument is malformed; `dealer_public_key_bytes` and `dealing` are of
///     note.
///   * the receiver has no share.
pub(super) fn complain_maybe<R: Rng + CryptoRng>(
    rng: &mut R,
    dkg_id: IDkgId,
    receiver_index: NodeIndex,
    receiver_secret_key: &EphemeralSecretKey,
    receiver_public_key: &EphemeralPublicKey,
    dealer_public_key_bytes: &EphemeralPublicKeyBytes,
    dealing: &CLibDealingBytes,
) -> Result<Option<CLibComplaintBytes>, DkgCreateResponseError> {
    let CLibDealingBytes {
        receiver_data,
        public_coefficients,
    } = dealing;
    // Parse:
    let my_receiver_data: ThresholdSecretKey =
        parse_my_receiver_data(receiver_data, receiver_index)?;
    let public_coefficients: PublicCoefficients =
        public_coefficients.try_into().map_err(|_: CryptoError| {
            DkgCreateResponseError::MalformedDealingError(MalformedDataError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "Malformed public coefficients".to_string(),
                data: None,
            })
        })?;
    let dealer_public_key = EphemeralPublicKey::try_from(dealer_public_key_bytes)
        .map_err(DkgCreateResponseError::MalformedPublicKeyError)?;

    // Compute share:
    let dh_between_receiver_and_dealer: EphemeralPublicKey =
        dealer_public_key.clone() * receiver_secret_key;
    let share: ThresholdSecretKey = dh::decrypt_share(
        dkg_id,
        &dealer_public_key,
        receiver_public_key,
        &dh_between_receiver_and_dealer,
        my_receiver_data,
    );

    // Verify share or complain
    if secret_key_is_consistent(share, &public_coefficients, receiver_index) {
        Ok(None)
    } else {
        let spec_r = EphemeralSecretKey::random(rng);
        let spec_t = EphemeralPublicKey::from(&spec_r);
        let spec_u = dealer_public_key * &spec_r;
        let spec_c: EphemeralSecretKey = ChallengeDigest {
            dkg_id,
            dealer_public_key_bytes: *dealer_public_key_bytes,
            receiver_public_key_bytes: EphemeralPublicKeyBytes::from(receiver_public_key),
            diffie_hellman: EphemeralPublicKeyBytes::from(&dh_between_receiver_and_dealer),
            spec_t: EphemeralPublicKeyBytes::from(&spec_t),
            spec_u: EphemeralPublicKeyBytes::from(&spec_u),
        }
        .digest();
        let spec_s: EphemeralSecretKey = {
            let mut ans = spec_c.clone();
            ans *= &receiver_secret_key; // spec: my_dh_secret
            ans += &spec_r;
            ans
        };
        Ok(Some(CLibComplaintBytes {
            diffie_hellman: EphemeralPublicKeyBytes::from(&dh_between_receiver_and_dealer),
            pok_challenge: EphemeralSecretKeyBytes::from(&spec_c),
            pok_response: EphemeralSecretKeyBytes::from(spec_s),
        }))
    }
}

fn parse_my_receiver_data(
    receiver_data: &[Option<EncryptedShareBytes>],
    receiver_index: NodeIndex,
) -> Result<ThresholdSecretKey, DkgCreateResponseError> {
    let my_receiver_data: &Option<EncryptedShareBytes> = {
        let index = usize::try_from(receiver_index).map_err(|_| {
            DkgCreateResponseError::SizeError(SizeError {
                message: format!("Unsupported receiver index: {}", receiver_index),
            })
        })?;
        receiver_data.get(index).ok_or_else(|| {
            DkgCreateResponseError::MalformedDealingError(MalformedDataError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: format!(
                    "Insufficient entries in dealing: index={} !< {}=length",
                    receiver_index,
                    receiver_data.len()
                ),
                data: None,
            })
        })?
    };
    let my_receiver_data: EncryptedShareBytes = my_receiver_data.ok_or(
        DkgCreateResponseError::MalformedDealingError(MalformedDataError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: format!("Receiver {} is missing a share", receiver_index),
            data: None,
        }),
    )?;
    ThresholdSecretKey::try_from(&my_receiver_data).map_err(|_| {
        DkgCreateResponseError::MalformedDealingError(MalformedDataError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: "Malformed share in dealing.".to_string(),
            data: None,
        })
    })
}

/// Verifies a single complaint against a dealing.
///
/// # Arguments
/// `dkg_id` - identifier for the key generation
/// `dealing` - the dealing that is being complained about
/// `receiver_index` - the index of the receiver making the complaint
/// `dealer_public_key_bytes` - the ephemeral public key of the dealer, not a
/// threshold key `receiver_public_key_bytes` - the ephemeral public key of the
/// receiver, not a threshold key `complaint` - the complaint being verified
/// # Panics
/// This method is not expected to panic
/// # Errors
/// This method SHALL return an error if:
/// * any of the fields is malformed.  Note that the caller MUST verify the
///   format of the dealing and public keys before calling this method, so this
///   SHOULD occur only if the complaint is malformed.
/// * the `receiver_index` is out of range for the dealing.
/// * the dealing has no share for the receiver.
/// * the complaint proof does not validate.
pub(super) fn verify_complaint(
    dkg_id: IDkgId,
    dealing: &CLibDealingBytes,
    receiver_index: NodeIndex,
    dealer_public_key_bytes: &EphemeralPublicKeyBytes,
    receiver_public_key_bytes: &EphemeralPublicKeyBytes,
    complaint_bytes: &CLibComplaintBytes,
) -> Result<(), DkgVerifyResponseError> {
    //  Parse:
    let complaint: CLibComplaint = complaint_bytes
        .try_into()
        .map_err(DkgVerifyResponseError::MalformedResponseError)?;
    let dealer_public_key = EphemeralPublicKey::try_from(dealer_public_key_bytes)
        .map_err(|e| DkgVerifyResponseError::MalformedResponseError(e.into()))?;
    let receiver_public_key = EphemeralPublicKey::try_from(receiver_public_key_bytes)
        .map_err(|e| DkgVerifyResponseError::MalformedResponseError(e.into()))?;
    let CLibDealingBytes {
        receiver_data,
        public_coefficients,
    } = dealing;
    let public_coefficients =
        PublicCoefficients::try_from(public_coefficients).map_err(|_: CryptoError| {
            DkgVerifyResponseError::MalformedResponseError(MalformedDataError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "Cannot parse public coefficients".to_string(),
                data: None,
            })
        })?; // Note: The AlgorithmId returned is that in the API, although the data is
             // actually used in Bls12_381 threshold signatures.

    let dealt_share: EncryptedShare = receiver_data
        .get(usize::try_from(receiver_index).map_err(|_| DkgVerifyResponseError::SizeError( SizeError {
            message: format!("Receiver index {} is too large for this machine", receiver_index),
        }))?)
        .ok_or_else(||DkgVerifyResponseError::InvalidReceiverIndexError(InvalidArgumentError {
            message: format!("Receiver index {} is out of bounds", receiver_index),
        }))?
        .ok_or(DkgVerifyResponseError::MalformedDealingError( MalformedDataError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: "Receiver has no dealing.  verified_dealing() implies that the receiver is not eligible.".to_string(),
            data: None,
        }))?
        .try_into().map_err(DkgVerifyResponseError::MalformedResponseError)?;

    // Verify:
    verify_pok(
        dkg_id,
        &complaint,
        complaint_bytes,
        &receiver_public_key,
        receiver_public_key_bytes,
        &dealer_public_key,
        dealer_public_key_bytes,
    )?;
    verify_share_is_bad(
        dkg_id,
        &complaint,
        &receiver_public_key,
        receiver_index,
        &dealer_public_key,
        &public_coefficients,
        dealt_share,
    )
}

/// Verifies that the complaint is indeed from the receiver
fn verify_pok(
    dkg_id: IDkgId,
    complaint: &CLibComplaint,
    complaint_bytes: &CLibComplaintBytes,
    receiver_public_key: &EphemeralPublicKey,
    receiver_public_key_bytes: &EphemeralPublicKeyBytes,
    dealer_public_key: &EphemeralPublicKey,
    dealer_public_key_bytes: &EphemeralPublicKeyBytes,
) -> Result<(), DkgVerifyResponseError> {
    let minus_hash = -complaint.pok_challenge.clone();

    let spec_t: EphemeralPublicKeyBytes = {
        let left = EphemeralPublicKey::from(&complaint.pok_response);
        let mut right = receiver_public_key.clone();
        right *= &minus_hash;
        (left + right).into()
    };

    let spec_u: EphemeralPublicKeyBytes = ((complaint.diffie_hellman.clone() * &minus_hash)
        + (dealer_public_key.clone() * &complaint.pok_response))
        .into();

    let spec_c = ChallengeDigest {
        dkg_id,
        dealer_public_key_bytes: *dealer_public_key_bytes,
        receiver_public_key_bytes: *receiver_public_key_bytes,
        diffie_hellman: complaint_bytes.diffie_hellman,
        spec_t,
        spec_u,
    }
    .digest();

    if complaint.pok_challenge != spec_c {
        Err(DkgVerifyResponseError::InvalidResponseError(
            InvalidArgumentError {
                message: "Invalid PoK in a complaint".to_string(),
            },
        ))
    } else {
        Ok(())
    }
}

/// Verifies that the secret share is inconsistent with the public coefficients
fn verify_share_is_bad(
    dkg_id: IDkgId,
    complaint: &CLibComplaint,
    receiver_public_key: &EphemeralPublicKey,
    receiver_index: NodeIndex,
    dealer_public_key: &EphemeralPublicKey,
    public_coefficients: &PublicCoefficients,
    dealt_share: EncryptedShare,
) -> Result<(), DkgVerifyResponseError> {
    let share: ThresholdSecretKey = dh::decrypt_share(
        dkg_id,
        dealer_public_key,
        receiver_public_key,
        complaint.diffie_hellman.clone(),
        dealt_share,
    );
    if secret_key_is_consistent(share, public_coefficients, receiver_index) {
        Err(DkgVerifyResponseError::InvalidResponseError(
            InvalidArgumentError {
                message: "CLibComplaint is about a valid message".to_string(),
            },
        ))
    } else {
        Ok(())
    }
}

struct ChallengeDigest {
    dkg_id: IDkgId,
    dealer_public_key_bytes: EphemeralPublicKeyBytes,
    receiver_public_key_bytes: EphemeralPublicKeyBytes,
    diffie_hellman: EphemeralPublicKeyBytes,
    spec_t: EphemeralPublicKeyBytes,
    spec_u: EphemeralPublicKeyBytes,
}
impl ChallengeDigest {
    fn digest(&self) -> EphemeralSecretKey {
        let mut hash = Sha256::new();
        hash.write(DomainSeparationContext::new(DOMAIN_POK_COMPLAINT).as_bytes());
        hash.write(&serde_cbor::to_vec(&self.dkg_id).expect("Failed to serialize DkgId")); // spec: dkg_id
        hash.write(&SECP256K1_PUBLIC_KEY_ONE.0); // spec: g_DH
        hash.write(&self.dealer_public_key_bytes.0); // spec: dh_snd
        hash.write(&self.receiver_public_key_bytes.0); // spec: my_dh
        hash.write(&self.diffie_hellman.0); // spec: dh_key
        hash.write(&self.spec_t.0); // spec: t
        hash.write(&self.spec_u.0); // spec: u
        Randomness::from(hash.finish()).into()
    }
}
