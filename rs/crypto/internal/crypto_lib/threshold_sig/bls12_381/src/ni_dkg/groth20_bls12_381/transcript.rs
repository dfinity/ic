//! Non-interactive key generation transcript methods.

use super::dealing::{
    verify_all_shares_are_present_and_well_formatted, verify_public_coefficients_match_threshold,
    verify_threshold,
};
use super::encryption::decrypt;
use crate::api::ni_dkg_errors;
use crate::ni_dkg::fs_ni_dkg::forward_secure::SecretKey as ForwardSecureSecretKey;
use crate::types as threshold_types;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381 as g20;
use ic_types::{NodeIndex, NumberOfNodes};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ops::{AddAssign, MulAssign};

// Code reuse
use crate::api::ni_dkg_errors::{
    CspDkgCreateReshareTranscriptError, CspDkgCreateTranscriptError, InvalidArgumentError,
    SizeError,
};

use crate::types::public_coefficients::conversions::pub_key_bytes_from_pub_coeff_bytes;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;

/// Creates an NiDKG transcript.
///
/// # Prerequisites
/// * The dealings MUST be verified before calling this method; otherwise
///   dealers may provide receivers with invalid shares.
///
/// # Errors
/// * `CspDkgCreateTranscriptError::SizeError` if `collection_threshold`  is
///   too large for this machine.
/// * `CspDkgCreateTranscriptError::InsufficientDealingsError` if `csp_dealings`
///   contains less than `collection_threshold` dealings.
/// * `CspDkgCreateTranscriptError::InvalidThresholdError` if the threshold is
///   either zero, or larger than the `number_of_receivers`.
/// * `CspDkgCreateTranscriptError::InvalidDealingError` if `csp_dealings` is
///   malformed or invalid.
///
/// # Panics
/// * If Langrange interpolation fails (because of duplicate x-coordinates).
pub fn create_transcript(
    threshold: NumberOfNodes,
    number_of_receivers: NumberOfNodes,
    csp_dealings: &BTreeMap<NodeIndex, g20::Dealing>,
    collection_threshold: NumberOfNodes,
) -> Result<g20::Transcript, CspDkgCreateTranscriptError> {
    let collection_threshold_usize = usize::try_from(collection_threshold.get()).map_err(|_| {
        CspDkgCreateTranscriptError::SizeError(SizeError {
            message: format!(
                "collection threshold is too large for this machine: {}",
                collection_threshold
            ),
        })
    })?;
    if csp_dealings.len() < collection_threshold_usize {
        return Err(CspDkgCreateTranscriptError::InsufficientDealingsError(
            InvalidArgumentError {
                message: format!(
                    "Insufficient dealings to create the transcript: found {} but required {} (=collection threshold).",
                    csp_dealings.len(),
                    collection_threshold_usize
                ),
            },
        ));
    }
    let csp_dealings = csp_dealings
        .iter()
        .take(collection_threshold_usize)
        .map(|(index, dealing)| (*index, dealing))
        .collect();
    compute_transcript(threshold, number_of_receivers, &csp_dealings)
}

/// Creates an NiDKG transcript with the same public key as an existing
/// threshold key.
///
/// # Prerequisites
/// * The dealings MUST be verified before calling this method; otherwise
///   dealers may provide receivers with invalid shares or dealers may provide
///   keys that do not preserve the public key.
///
/// # Errors
/// * `CspDkgCreateReshareTranscriptError::InsufficientDealingsError` if the
///   length of `csp_dealings` is smaller than the new threshold (set by
///   `resharing_public_coefficients`).
/// * `CspDkgCreateReshareTranscriptError::ResharingFailed` if the public key
///   created by this resharing does not match the previous public key.
/// * `CspDkgCreateTranscriptError::InvalidThresholdError` if the threshold is
///   either zero, or larger than the `number_of_receivers`.
/// * `CspDkgCreateTranscriptError::InvalidDealingError` if `csp_dealings` is
///   malformed or invalid.
///
/// # Panics
/// * If Langrange interpolation fails (because of duplicate x-coordinates).
pub fn create_resharing_transcript(
    threshold: NumberOfNodes,
    number_of_receivers: NumberOfNodes,
    csp_dealings: &BTreeMap<NodeIndex, g20::Dealing>,
    resharing_public_coefficients: &PublicCoefficientsBytes,
) -> Result<g20::Transcript, CspDkgCreateReshareTranscriptError> {
    // Take the requisite number of dealings
    let resharing_threshold = resharing_public_coefficients.coefficients.len();
    if csp_dealings.len() < resharing_threshold {
        let error = InvalidArgumentError {
            message: format!(
                "Insufficient dealings ({}) to reshare keys with threshold ({}).",
                csp_dealings.len(),
                resharing_threshold
            ),
        };
        return Err(CspDkgCreateReshareTranscriptError::InsufficientDealingsError(error));
    }
    let csp_dealings = csp_dealings
        .iter()
        .take(resharing_threshold)
        .map(|(dealer_index, dealing)| (*dealer_index, dealing))
        .collect();

    // Compute the transcript
    let transcript = compute_transcript(threshold, number_of_receivers, &csp_dealings)?;

    // Verify that the public key is unchanged
    let public_coefficients = PublicCoefficientsBytes {
        coefficients: transcript.public_coefficients.coefficients.clone(),
    };
    if pub_key_bytes_from_pub_coeff_bytes(resharing_public_coefficients)
        != pub_key_bytes_from_pub_coeff_bytes(&public_coefficients)
    {
        let error = InvalidArgumentError {
            message: format!(
                "Resharing failed.  Have the dealings been verified?:\n  Old public key: {:?}\n  New public key: {:?}",
                pub_key_bytes_from_pub_coeff_bytes(resharing_public_coefficients),
                pub_key_bytes_from_pub_coeff_bytes(&public_coefficients)
            ),
        };
        return Err(CspDkgCreateReshareTranscriptError::ResharingFailed(error));
    }

    Ok(transcript)
}

/// Computes the transcript using all provided dealings
///
/// Note: The caller can optimise by providing a minimal number of dealings.
///
/// # Panics
/// * If Langrange interpolation fails (because of duplicate x-coordinates).
fn compute_transcript(
    threshold: NumberOfNodes,
    number_of_receivers: NumberOfNodes,
    csp_dealings: &BTreeMap<NodeIndex, &g20::Dealing>,
) -> Result<g20::Transcript, CspDkgCreateTranscriptError> {
    // Extract and verify the data we need from the arguments
    verify_threshold(threshold, number_of_receivers)
        .map_err(CspDkgCreateTranscriptError::InvalidThresholdError)?;

    let receiver_data: Result<BTreeMap<NodeIndex, g20::EncryptedShares>, _> = csp_dealings
        .iter()
        .map(|(dealer_index, dealing)| {
            verify_all_shares_are_present_and_well_formatted(dealing, number_of_receivers)
                .map_err(|error| CspDkgCreateTranscriptError::InvalidDealingError {
                    dealer_index: *dealer_index,
                    error,
                })?;
            verify_public_coefficients_match_threshold(dealing, threshold).map_err(|error| {
                CspDkgCreateTranscriptError::InvalidDealingError {
                    dealer_index: *dealer_index,
                    error,
                }
            })?;
            Ok((*dealer_index, dealing.ciphertexts.clone()))
        })
        .collect();
    let receiver_data = receiver_data?;

    let individual_public_coefficients: Result<
        BTreeMap<NodeIndex, threshold_types::PublicCoefficients>,
        _,
    > = csp_dealings
        .iter()
        .map(|(dealer_index, dealing)| {
            // Type conversion from crypto internal type.
            // The dealings have already been verified,
            // so we can trust the serialized coefficients.
            threshold_types::PublicCoefficients::from_trusted_bytes(&dealing.public_coefficients)
                .map(|public_coefficients| (*dealer_index, public_coefficients))
                .map_err(|crypto_error| {
                    let error = InvalidArgumentError {
                        message: format!("Invalid dealing: {:?}", crypto_error),
                    };
                    CspDkgCreateTranscriptError::InvalidDealingError {
                        dealer_index: *dealer_index,
                        error,
                    }
                })
        })
        .collect();
    let individual_public_coefficients = individual_public_coefficients?;

    // Combine the dealings
    let public_coefficients: g20::PublicCoefficientsBytes = {
        let lagrange_coefficients = {
            let reshare_x: Vec<NodeIndex> = csp_dealings.keys().copied().collect();

            threshold_types::PublicCoefficients::lagrange_coefficients_at_zero(&reshare_x)
                .expect("Cannot fail because all x are distinct.")
        };

        let mut combined_public_coefficients = threshold_types::PublicCoefficients::zero();

        for ((_dealer_index, individual), factor) in individual_public_coefficients
            .into_iter()
            .zip(lagrange_coefficients)
        {
            // Aggregate the public coefficients:
            combined_public_coefficients += individual * factor;
        }

        // This type conversion is needed because of the internal/CSP type duplication.
        g20::PublicCoefficientsBytes::from(&combined_public_coefficients)
    };

    Ok(g20::Transcript {
        public_coefficients,
        receiver_data,
    })
}

/// Computes a participant's threshold signing key from the DKG transcript.
///
/// # Arguments
/// * `transcript` - The transcript of the distributed key generation ceremony.
/// * `receiver_index` - The index of the receiver whose signing key is
///   computed.
/// * `fs_secret_key` - The forward-secure decryption key of the given
///   `receiver_index`.
/// * `epoch` - The forward-secure decryption epoch to use.
///
/// # Errors
/// * `CspDkgLoadPrivateKeyError::InvalidTranscriptError` if decryption of the
///   share fails, or the share is invalid.
///
/// # Panics
/// * If Langrange interpolation fails (because of duplicate x-coordinates).
/// * Transcript serialization fails (during creation of an error message).
pub fn compute_threshold_signing_key(
    transcript: &g20::Transcript,
    receiver_index: NodeIndex,
    fs_secret_key: &ForwardSecureSecretKey,
    epoch: g20::Epoch,
) -> Result<threshold_types::SecretKeyBytes, ni_dkg_errors::CspDkgLoadPrivateKeyError> {
    // Get my shares
    let shares_from_each_dealer: Result<BTreeMap<NodeIndex, threshold_types::SecretKey>, _> =
        transcript
            .receiver_data
            .iter()
            .map(|(dealer_index, encrypted_shares)| {
                let secret_key = decrypt(
                    encrypted_shares,
                    fs_secret_key,
                    receiver_index,
                    epoch,
                    &dealer_index.to_be_bytes(),
                )
                .map_err(|error| match error {
                    ni_dkg_errors::DecryptError::EpochTooOld {
                        ciphertext_epoch,
                        secret_key_epoch,
                    } => ni_dkg_errors::CspDkgLoadPrivateKeyError::EpochTooOldError {
                        ciphertext_epoch,
                        secret_key_epoch,
                    },
                    error => {
                        let message = format!(
                            "Dealing #{}: could not get share for receiver #{}.\n {:#?}",
                            dealer_index, receiver_index, error
                        );
                        let error = InvalidArgumentError { message };
                        ni_dkg_errors::CspDkgLoadPrivateKeyError::InvalidTranscriptError(error)
                    }
                })?;

                Ok((*dealer_index, secret_key))
            })
            .collect();
    let shares_from_each_dealer = shares_from_each_dealer?;

    // Interpolate
    let combined_shares = {
        let lagrange_coefficients = {
            let reshare_x: Vec<NodeIndex> = shares_from_each_dealer.keys().copied().collect();

            threshold_types::PublicCoefficients::lagrange_coefficients_at_zero(&reshare_x)
                .expect("Cannot fail because all x are distinct.")
        };

        let mut combined_shares = threshold_types::SecretKey::zero();

        for ((_dealer_index, mut share), factor) in shares_from_each_dealer
            .into_iter()
            .zip(lagrange_coefficients)
        {
            // Aggregate the shares:
            share.mul_assign(&factor);
            combined_shares.add_assign(&share);
        }
        threshold_types::SecretKeyBytes::from(combined_shares)
    };
    Ok(combined_shares)
}
