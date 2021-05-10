//! (deprecated) Dealing phase of Interactive Distributed Key Generation.

use super::dh;
use crate::api::dkg_errors::{
    DkgCreateDealingError, DkgCreateReshareDealingError, DkgVerifyDealingError,
    DkgVerifyReshareDealingError, InvalidArgumentError, MalformedDataError,
    MalformedSecretKeyError, SizeError,
};
use crate::types::public_coefficients::conversions::pub_key_bytes_from_pub_coeff_bytes;
use crate::{
    api::individual_public_key,
    crypto::{keygen, keygen_with_secret},
    dkg::secp256k1::types::{
        CLibDealingBytes, EncryptedShareBytes, EphemeralPopBytes, EphemeralPublicKey,
        EphemeralPublicKeyBytes, EphemeralSecretKey, EphemeralSecretKeyBytes,
    },
    types::{
        PublicCoefficients, SecretKey as ThresholdSecretKey,
        SecretKeyBytes as ThresholdSecretKeyBytes,
    },
};
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::PublicKeyBytes;
use ic_types::{
    crypto::{AlgorithmId, CryptoError},
    IDkgId, NodeIndex, NumberOfNodes, Randomness,
};
use std::convert::{TryFrom, TryInto};

#[cfg(test)]
mod test_resharing;
#[cfg(test)]
mod tests;

/// Creates a new dealing: Generates threshold keys, encrypts each secret key.
///
/// # Arguments
/// * `seed` - a secret random number used to generate the threshold keys.
/// * `dealer_secret_key_bytes` - the dealer's ephemeral key, used to encrypt
///   shares.
/// * `dkg_id` is the identifier of the DKG instance this dealing is used for.
/// * `threshold` - the minimum number of receivers needed to sign a valid
///   threshold signature.
/// * `receiver_keys` - the ephemeral public keys of the receivers, used to
///   encrypt their shares.  Given that some receivers may be ineligible this
///   takes the standard form `<Vec<Option<EphemeralPublicKey>>`, where:
///     * the index in the vector corresponds to the receiver index
///     * the `Option` is set to `None` for ineligible, discredited or otherwise
///       non-participating receivers.
/// # Panics
/// * Threshold keys should be generated for every participating receiver.  This
///   method panics if there is a mismatch, i.e.:
///   * there is a receiver with an ephemeral key for which no threshold key is
///     generated, OR
///   * there is a receiver with no ephemeral key for which a threshold key is
///     generated.
/// # Errors
/// * The number of eligible receivers should be equal to or greater than the
///   threshold; otherwise this MUST return an error.  Note: This is checked in
///   the threshold library by `keygen(..)`.
/// * The public keys must be well formed, otherwise this MUST return an error.
/// # Returns
/// The returned data structure contains the threshold public coefficients and
/// encrypted threshold secret keys.  Each encrypted secret key can be decrypted
/// by the corresponding receiver.
pub fn create_dealing(
    seed: Randomness,
    dealer_secret_key_bytes: EphemeralSecretKeyBytes,
    dkg_id: IDkgId,
    threshold: NumberOfNodes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
) -> Result<CLibDealingBytes, DkgCreateDealingError> {
    let (bls_public_coefficients, bls_secret_keys) = {
        let selected_nodes: Vec<bool> = receiver_keys.iter().map(|x| x.is_some()).collect();
        keygen(seed, threshold, &selected_nodes[..])
    }
    .map_err(CryptoError::from)
    .map_err(DkgCreateDealingError::UnsupportedThresholdParameters)?;

    let public_coefficients = PublicCoefficientsBytes::from(&bls_public_coefficients);

    let receiver_data = create_receiver_data(
        dkg_id,
        dealer_secret_key_bytes,
        receiver_keys,
        &bls_secret_keys,
    )?;

    Ok(CLibDealingBytes {
        public_coefficients,
        receiver_data,
    })
}

/// Creates a resharing dealing.
///
/// The special property of a resharing key generation is that the dealer
/// predefines the combined threshold secret key.
///
/// # Arguments
/// * `seed` is a secret random number used to generate the threshold keys.
/// * `dealer_ephemeral_secret_key_bytes` is used to encrypt shares.
/// * `threshold` is the minimum number of receivers needed to sign a valid
///   threshold signature.
/// * `dkg_id` is the identifier of the DKG instance this dealing is used for.
/// * `receiver_keys` is the ephemeral public keys of the receivers, used to
///   encrypt their shares.  Given that some receivers may be ineligible this
///   takes the standard form `<Vec<Option<EphemeralPublicKey>>`, where:
///     * the index in the vector corresponds to the receiver index
///     * the `Option` is set to `None` for ineligible, discredited or otherwise
///       non-participating receivers.
/// * `reshared_threshold_secret_key` is the dealer's preceding threshold secret
///   key; it is shared in this dealing.
/// # Panics
/// * Threshold keys should be generated for every participating receiver.  This
///   method panics if there is a mismatch, i.e.:
///   * there is a receiver with an ephemeral key for which no threshold key is
///     generated, OR
///   * there is a receiver with no ephemeral key for which a threshold key is
///     generated.
/// # Errors
/// * The number of eligible receivers should be equal to or greater than the
///   threshold; otherwise this MUST return an error.  Note: This is checked in
///   the threshold library by `keygen(..)`.
/// * The public keys must be well formed, otherwise this MUST return an error.
/// * `reshared_secret_key` must be well formed, otherwise this MUST return an
///   error.
/// # Returns
/// The returned data structure contains the threshold public coefficients and
/// encrypted threshold secret keys.  Each encrypted secret key can be decrypted
/// by the corresponding receiver.
#[allow(unused)]
pub fn create_resharing_dealing(
    seed: Randomness,
    dealer_ephemeral_secret_key_bytes: EphemeralSecretKeyBytes,
    dkg_id: IDkgId,
    threshold: NumberOfNodes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
    reshared_threshold_secret_key_bytes: ThresholdSecretKeyBytes,
) -> Result<CLibDealingBytes, DkgCreateReshareDealingError> {
    let reshared_threshold_secret_key: ThresholdSecretKey = (&reshared_threshold_secret_key_bytes)
        .try_into()
        .map_err(|_| {
            DkgCreateReshareDealingError::MalformedSecretKeyError(MalformedSecretKeyError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "Malformed reshared secret key".to_string(),
            })
        })?;
    let (bls_public_coefficients, bls_secret_keys) = {
        let selected_nodes: Vec<bool> = receiver_keys.iter().map(|x| x.is_some()).collect();
        keygen_with_secret(
            seed,
            threshold,
            &selected_nodes[..],
            &reshared_threshold_secret_key,
        )
    }
    .map_err(CryptoError::from)
    .map_err(DkgCreateReshareDealingError::UnsupportedThresholdParameters)?;

    let public_coefficients = PublicCoefficientsBytes::from(&bls_public_coefficients);

    let receiver_data = create_receiver_data(
        dkg_id,
        dealer_ephemeral_secret_key_bytes,
        receiver_keys,
        &bls_secret_keys[..],
    )?;

    // CSP
    Ok(CLibDealingBytes {
        public_coefficients,
        receiver_data,
    })
}

/// Create the receiver data which contains the encrypted threshold secret keys
/// for all eligible receivers.
///
/// # Arguments
/// * `dkg_id` is the identifier of the DKG instance.
/// * `dealer_secret_key_bytes` is the dealer's ephemeral secret key, used to
///   encrypt shares.
/// * `receiver_keys` is the ephemeral public keys of the receivers, used to
///   encrypt their shares.  Given that some receivers may be ineligible this
///   takes the standard form `<Vec<Option<EphemeralPublicKey>>`, where:
///     * the index in the vector corresponds to the receiver index
///     * the `Option` is set to `None` for ineligible, discredited or otherwise
///       non-participating receivers.
/// * `threshold_secret_keys` is the threshold secret keys of the receivers to
///   be encrypted.
/// # Panics
/// * Threshold keys should be generated for every participating receiver.  This
///   method panics if there is a mismatch, i.e.:
///   * there is a receiver with an ephemeral key for which no threshold key is
///     generated, OR
///   * there is a a receiver with no ephemeral key for which a threshold key is
///     generated.
/// # Errors
/// * The public keys must be well formed, otherwise this MUST return an error.
/// # Returns
/// The encrypted threshold secret keys of eligible receivers.  
/// Each encrypted secret key can be decrypted by the corresponding receiver.
fn create_receiver_data(
    dkg_id: IDkgId,
    dealer_ephemeral_secret_key_bytes: EphemeralSecretKeyBytes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
    threshold_secret_keys: &[Option<ThresholdSecretKey>],
) -> Result<Vec<Option<EncryptedShareBytes>>, DkgCreateDealingError> {
    let dealer_secret_key = EphemeralSecretKey::try_from(dealer_ephemeral_secret_key_bytes)
        .map_err(DkgCreateDealingError::MalformedSecretKeyError)?;
    let dealer_public_key = EphemeralPublicKey::from(&dealer_secret_key); // TODO(DFN-845): Store the public key with the secret key to avoid recomputing
                                                                          // it.

    receiver_keys
        .iter()
        .zip(threshold_secret_keys)
        .map(|(receiver_key_maybe, bls_secret_key_maybe)| {
            match (receiver_key_maybe, bls_secret_key_maybe) {
                (None, None) => Ok(None),
                (None, Some(_)) => panic!("No receiver for threshold key"),
                (Some(_), None) => panic!("No threshold key for receiver"),
                (Some((receiver_key_bytes, _pop)), Some(bls_secret_key)) => {
                    EphemeralPublicKey::try_from(receiver_key_bytes)
                        .map_err(DkgCreateDealingError::MalformedPublicKeyError)
                        .map(|receiver_public_key: EphemeralPublicKey| {
                            let dh_secret = receiver_public_key.clone() * &dealer_secret_key;
                            let encrypted_share = EncryptedShareBytes::from(&dh::encrypt_share(
                                dkg_id,
                                &dealer_public_key,
                                &receiver_public_key,
                                &dh_secret,
                                *bls_secret_key,
                            ));
                            Some(encrypted_share)
                        })
                }
            }
        })
        .collect()
}

/// Verifies the public parameters of the dealing (degree and group size)
///
/// # Arguments
/// * `threshold` - the minimum number of receivers needed to sign a valid
///   threshold signature.
/// * `receiver_keys` - the ephemeral public keys of the receivers, used to
///   encrypt their shares.  Given that some receivers may be ineligible this
///   takes the standard form `<Vec<Option<EphemeralPublicKey>>`, where:
///     * the index in the vector corresponds to the receiver index
///     * the `Option` is set to `None` for ineligible, discredited or otherwise
///       non-participating receivers.
/// * `dealing` - the dealing being verified.
/// # Panics
/// This method is not expected to panic
/// # Errors
/// This method returns an error if:
/// * the public coefficients or receiver data are malformed;
/// * the number of public coefficients does not match the threshold;
/// * the length of `dealing.receiver_data` is not the same as the length of
///   `receiver_keys`;
/// * the set of receivers with a share does not match the set with public keys,
///   i.e. `dealing.receiver_data[i]` is `Some` where `receiver_keys[i]` is None
///   or vice versa.
pub fn verify_dealing(
    threshold: NumberOfNodes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
    dealing: CLibDealingBytes,
) -> Result<(), DkgVerifyDealingError> {
    // Parse inputs:
    let CLibDealingBytes {
        public_coefficients,
        receiver_data,
    } = dealing;
    let public_coefficients: PublicCoefficients =
        (&public_coefficients).try_into().map_err(|_| {
            DkgVerifyDealingError::MalformedDealingError(MalformedDataError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "public coefficients could not be parsed".to_string(),
                data: None,
            })
        })?;
    let receiver_data: Result<Vec<Option<ThresholdSecretKey>>, _> = receiver_data
        .iter()
        .map(|share_maybe| share_maybe.map(ThresholdSecretKey::try_from).transpose())
        .collect();
    let receiver_data = receiver_data.map_err(DkgVerifyDealingError::MalformedDealingError)?;

    // The public coefficients should match the threshold.
    let public_coefficients_threshold =
        NumberOfNodes::try_from(&public_coefficients).map_err(|_| {
            DkgVerifyDealingError::SizeError(SizeError {
                message: format!(
                    "More receivers than this machine can handle: {}",
                    public_coefficients.coefficients.len()
                ),
            })
        })?;
    if public_coefficients_threshold != threshold {
        return Err(DkgVerifyDealingError::InvalidDealingError(
            InvalidArgumentError {
                message: format!(
                    "Incorrect threshold: dealing threshold={} != {}=expected threshold",
                    public_coefficients_threshold, threshold
                ),
            },
        ));
    }

    // The number of receiver slots should match.
    if receiver_data.len() != receiver_keys.len() {
        return Err(DkgVerifyDealingError::InvalidDealingError(
            InvalidArgumentError {
                message: format!(
                    "Incorrect share vector length: share slots={} != {}=receiver slots",
                    receiver_data.len(),
                    receiver_keys.len()
                ),
            },
        ));
    }

    // Every receiver that has keys should have a share:
    if let Some((index, (data, key))) = receiver_data
        .iter()
        .zip(receiver_keys)
        .enumerate()
        .find(|(_index, (data, key))| data.is_some() != key.is_some())
    {
        return Err(DkgVerifyDealingError::InvalidDealingError(
            InvalidArgumentError {
                message: format!(
                    "Receiver {} has key={} != {}=has share",
                    index,
                    data.is_some(),
                    key.is_some()
                ),
            },
        ));
    }
    Ok(())
}

/// Verifies the public parameters of the dealing.
///
/// This performs the same checks as `verify_dealing` but additionally verifies
/// that the new threshold public key is the same as the individual threshold
/// public key of the dealer in the reshared parameters.
///
/// # Arguments
/// * `threshold` is the minimum number of receivers needed to sign a valid
///   threshold signature.
/// * `receiver_keys` is the ephemeral public keys of the receivers, used to
///   encrypt their shares.  Given that some receivers may be ineligible this
///   takes the standard form `<Vec<Option<EphemeralPublicKey>>`, where:
///     * the index in the vector corresponds to the receiver index
///     * the `Option` is set to `None` for ineligible, discredited or otherwise
///       non-participating receivers.
/// * `dealing` is the dealing being verified.
/// * `dealer_index` is the index of the dealer as a receiver in the preceding
///   threshold key.
/// * `resharing_public_coefficients` are the public coefficients of the
///   preceding threshold key.
/// # Panics
/// This method is not expected to panic
/// # Errors
/// This method returns an error if:
/// * the public coefficients or receiver data are malformed;
/// * the number of public coefficients does not match the threshold;
/// * the length of `dealing.receiver_data` is not the same as the length of
///   `receiver_keys`;
/// * the set of receivers with a share does not match the set with public keys,
///   i.e. `dealing.receiver_data[i]` is `Some` where `receiver_keys[i]` is None
///   or vice versa.
/// * the new threshold public key does not match the previous individual public
///   key of the dealer.
#[allow(unused)]
pub fn verify_resharing_dealing(
    threshold: NumberOfNodes,
    receiver_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
    dealing: CLibDealingBytes,
    dealer_index: NodeIndex,
    resharing_public_coefficients: PublicCoefficientsBytes,
) -> Result<(), DkgVerifyReshareDealingError> {
    // The dealer should be resharing their own threshold key:
    {
        let reshared_individual_public_key: PublicKeyBytes = {
            individual_public_key(&resharing_public_coefficients, dealer_index)
                    .map_err(|error| {
                        DkgVerifyReshareDealingError::MalformedPublicCoefficientsError(
                            MalformedDataError {
                                algorithm: AlgorithmId::Secp256k1,
                                internal_error: format!("Reshared public coefficients do not yield dealer's individual public key: {:?}", error),
                                data: None,
                            },
                        )
                    })
        }?;
        let dealt_threshold_public_key =
            pub_key_bytes_from_pub_coeff_bytes(&dealing.public_coefficients);
        if dealt_threshold_public_key != reshared_individual_public_key {
            return Err(DkgVerifyReshareDealingError::InvalidDealingError(InvalidArgumentError{ message: format!("Dealt threshold public key does not match reshared individual public key:\n  {:?} !=\n  {:?}", dealt_threshold_public_key, reshared_individual_public_key) }));
        }
    }

    // All the usual tests for a valid dealing apply:
    verify_dealing(threshold, receiver_keys, dealing)?;

    Ok(())
}
