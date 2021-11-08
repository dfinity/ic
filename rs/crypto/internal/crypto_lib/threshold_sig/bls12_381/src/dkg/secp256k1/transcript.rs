//! (deprecated) Transcript management for interactive distributed key
//! generation.

use crate::api::dkg_errors::{
    DkgCreateReshareTranscriptError, DkgCreateTranscriptError, DkgLoadPrivateKeyError,
    InvalidArgumentError, MalformedDataError, SizeError,
};
use crate::crypto::x_for_index;
use crate::dkg::secp256k1::dh::key_encryption_key;
use crate::{
    crypto::secret_key_is_consistent,
    dkg::secp256k1::types::{
        CLibDealing, CLibDealingBytes, CLibTranscriptBytes, CLibVerifiedResponseBytes,
        EncryptedShare, EncryptedShareBytes, EphemeralPopBytes, EphemeralPublicKey,
        EphemeralPublicKeyBytes, EphemeralSecretKey, EphemeralSecretKeyBytes,
    },
    types::{
        PublicCoefficients, SecretKey as ThresholdSecretKey,
        SecretKeyBytes as ThresholdSecretKeyBytes,
    },
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_types::{crypto::AlgorithmId, IDkgId, NodeIndex, NumberOfNodes};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::iter::Sum;
use std::ops::{AddAssign, MulAssign, SubAssign};

#[cfg(test)]
mod test_resharing;
#[cfg(test)]
mod tests;

/// Combines all valid dealings into a short transcript.
///
/// Note:  Responses containing at least one invalid
/// complaint are excluded, even if other complaints are valid.
///
/// # Arguments
/// * `threshold` - the minimum number of signatures needed for a valid
///   threshold signature.
/// * `verified_dealings` - the dealings that passed initial verification. Note:
///   This takes the standard form for per-dealer data:  A map from the dealer's
///   public key to the dealing.
/// * `verified_responses` - the responses that passed initial verification.
///   Note: this takes the standard form for per-receiver data:  A vector of
///   options which are `Some` for valid receivers and `None` for disqualified
///   or non-participating receivers.
/// # Prerequisites
/// * We assume that all dealings are consistent with the threshold.  This
///   SHOULD have been confirmed when validating the dealings.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// This method MUST return an error if:
/// * Any arguments are malformed.
/// * The number of dealings is not at least `threshold`.
/// * The number of responses is not at least `2 * threshold - 1`.
/// * The number of valid dealings is not at least `1`.
pub fn create_transcript(
    threshold: NumberOfNodes,
    verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    verified_responses: &[Option<CLibVerifiedResponseBytes>],
) -> Result<CLibTranscriptBytes, DkgCreateTranscriptError> {
    let dealings =
        transcript_util::get_valid_dealings(threshold, verified_dealings, verified_responses)?;
    let receiver_data =
        transcript_util::simple::combine_receiver_shares(&dealings, verified_responses)?;
    let public_coefficients = transcript_util::simple::combine_public_coefficients(&dealings)?;
    let dealer_public_keys: Vec<EphemeralPublicKeyBytes> = dealings.keys().cloned().collect();

    Ok(CLibTranscriptBytes {
        dealer_public_keys,
        public_coefficients,
        receiver_data,
        dealer_reshare_indices: None,
    })
}

/// Combines all valid resharing dealings into a short transcript.
///
/// Note:  This is similar to the normal `create_transcript` except for the
/// mechanics of combining dealings.
///
/// # Arguments
/// * `threshold` is the minimum number of signatures needed for a valid
///   threshold signature.
/// * `verified_dealings` are the dealings that passed initial verification.
///   Note: This takes the standard form for per-dealer data:  A map from the
///   dealer's public key to the dealing.
/// * `verified_responses` are the responses that passed initial verification.
///   Note: this takes the standard form for per-receiver data:  A vector of
///   options which are `Some` for valid receivers and `None` for disqualified
///   or non-participating receivers.
/// * `dealer_keys` are the ephemeral keys of the dealers.  The position of the
///   dealer in the representation should match their position as a signatory in
///   the preceding threshold key.
/// * `resharing_public_coefficients` are the public coefficients of the
///   preceding threshold key.
/// # Prerequisites
/// * We assume that all dealings are consistent with the threshold.  This
///   SHOULD have been confirmed when validating the dealings.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// This method MUST return an error if:
/// * Any arguments are malformed.
/// * The number of dealings is not at least `threshold`.
/// * The number of responses is not at least `2 * threshold - 1`.
/// * The number of valid dealings is not at least the threshold of the
///   preceding threshold key.
#[allow(unused)]
pub fn create_resharing_transcript(
    threshold: NumberOfNodes,
    verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    verified_responses: &[Option<CLibVerifiedResponseBytes>],
    dealer_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
    resharing_public_coefficients: &PublicCoefficientsBytes,
) -> Result<CLibTranscriptBytes, DkgCreateReshareTranscriptError> {
    // Get the dealer information:
    let (selected_dealer_indices, selected_dealer_public_keys, selected_dealings) =
        transcript_util::resharing::select_dealer_data(
            threshold,
            verified_dealings,
            verified_responses,
            dealer_keys,
            resharing_public_coefficients,
        )?;

    // Get the public keys of the receivers:
    let receiver_key_bytes: Vec<Option<EphemeralPublicKeyBytes>> = verified_responses
        .iter()
        .map(|response_maybe| {
            response_maybe
                .as_ref()
                .map(|response| response.receiver_public_key)
        })
        .collect();

    // Combine dealings:
    let (public_coefficients, receiver_data): (PublicCoefficients, Vec<Option<EncryptedShare>>) =
        transcript_util::resharing::combine_public_coefficients_and_receiver_shares(
            &selected_dealer_indices,
            selected_dealings,
            &receiver_key_bytes,
        );

    // Assemble the transcript:
    let public_coefficients = PublicCoefficientsBytes::from(&public_coefficients);
    let receiver_data: Vec<Option<(EphemeralPublicKeyBytes, EncryptedShareBytes)>> = receiver_data
        .iter()
        .map(|data_maybe| data_maybe.map(EncryptedShareBytes::from))
        .zip(&receiver_key_bytes)
        .map(|tuple| match tuple {
            (Some(data), Some(key)) => Some((*key, data)),
            _ => None,
        })
        .collect();
    Ok(CLibTranscriptBytes {
        dealer_public_keys: selected_dealer_public_keys,
        public_coefficients,
        receiver_data,
        dealer_reshare_indices: Some(selected_dealer_indices),
    })
}

/// Methods used when creating a transcript.
mod transcript_util {
    use super::*;
    pub fn compute_num_responses(
        verified_responses: &[Option<CLibVerifiedResponseBytes>],
    ) -> Result<NodeIndex, DkgCreateTranscriptError> {
        if NodeIndex::try_from(verified_responses.len()).is_err() {
            return Err(DkgCreateTranscriptError::SizeError(SizeError {
                message: "Too many receivers".to_string(),
            }));
        }
        Ok(NodeIndex::try_from(verified_responses.iter().filter(|response_maybe| response_maybe.is_some()).count())
        .expect("This can never fail: num_responses is less than or equal to verified_responses.len() and we check the size of the latter above."))
    }

    pub fn compute_num_dealings(
        verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
    ) -> Result<NodeIndex, DkgCreateTranscriptError> {
        NodeIndex::try_from(verified_dealings.len()).map_err(|_| {
            DkgCreateTranscriptError::SizeError(SizeError {
                message: "Too many dealings".to_string(),
            })
        })
    }

    /// If the threshold is too high, the required number of responses cannot be
    /// reached.
    ///
    /// The somewhat contorted arithmetic is to avoid wrapping errors.
    ///
    /// Hypothetical examples:
    /// * NodeIndex::max_value == 2**16-1
    ///   * max threshold == 2**15
    ///   * required num_responses == 2*threshold-1 == 2**16-1
    /// * NodeIndex::max_value == 2**16
    ///   * max threshold == 2**15
    ///   * required num_responses == 2*threshold-1
    pub fn check_threshold_is_feasible(
        threshold: NumberOfNodes,
    ) -> Result<(), DkgCreateTranscriptError> {
        if threshold.get() > (NodeIndex::max_value() - 1) / 2 + 1 {
            return Err(DkgCreateTranscriptError::InvalidThresholdError(
                InvalidArgumentError {
                    message: "Threshold too high".to_string(),
                },
            ));
        }
        Ok(())
    }

    /// Check that we have at least threshold dealings and 2*threshold-1
    /// responses.
    pub fn check_threshold_is_met(
        threshold: NumberOfNodes,
        num_dealings: NodeIndex,
        num_responses: NodeIndex,
    ) -> Result<(), DkgCreateTranscriptError> {
        if num_dealings < threshold.get()
            || num_responses == 0
            || threshold.get() > (num_responses - 1) / 2 + 1
        {
            return Err(DkgCreateTranscriptError::InsufficientDataError(InvalidArgumentError {
            message: format!("Insufficient information to run DKG safely. threshold: {} num_dealings: {} num_responses: {}", threshold, num_dealings, num_responses),
        }));
        }
        Ok(())
    }

    /// Remove the dealings that have valid complaints.
    pub fn filter_dealings(
        verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
        verified_responses: &[Option<CLibVerifiedResponseBytes>],
    ) -> Result<BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>, DkgCreateTranscriptError> {
        let dealings: BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes> = {
            let mut dealings = verified_dealings.clone();
            for response in verified_responses.iter().flatten() {
                for (dealer_public_key, complaint_maybe) in response.complaints.iter() {
                    if complaint_maybe.is_some() {
                        dealings.remove(dealer_public_key);
                    }
                }
            }
            dealings
        };

        if dealings.is_empty() {
            return Err(DkgCreateTranscriptError::InsufficientDataError(
                InvalidArgumentError {
                    message: "Insufficient dealings to run DKG safely".to_string(),
                },
            ));
        }
        Ok(dealings)
    }

    pub fn get_valid_dealings(
        threshold: NumberOfNodes,
        verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
        verified_responses: &[Option<CLibVerifiedResponseBytes>],
    ) -> Result<BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>, DkgCreateTranscriptError> {
        let num_responses: NodeIndex = transcript_util::compute_num_responses(verified_responses)?;
        let num_dealings: NodeIndex = transcript_util::compute_num_dealings(verified_dealings)?;
        transcript_util::check_threshold_is_feasible(threshold)?;
        transcript_util::check_threshold_is_met(threshold, num_dealings, num_responses)?;
        transcript_util::filter_dealings(verified_dealings, verified_responses)
    }

    /// Methods used by the simple DKG
    pub mod simple {
        use super::*;
        pub fn combine_public_coefficients(
            dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
        ) -> Result<PublicCoefficientsBytes, DkgCreateTranscriptError> {
            let all_public_coefficients: Result<Vec<PublicCoefficients>, _> = dealings
                .iter()
                .map(|(_dealer_public_key, dealing)| {
                    PublicCoefficients::try_from(&dealing.public_coefficients)
                })
                .collect();
            let all_public_coefficients = all_public_coefficients.map_err(|_| {
                DkgCreateTranscriptError::MalformedDealingError(MalformedDataError {
                    algorithm: AlgorithmId::Secp256k1,
                    internal_error: "Malformed public coefficients".to_string(),
                    data: None,
                })
            })?;
            Ok(PublicCoefficients::sum(all_public_coefficients.iter()).into())
        }

        pub fn combine_receiver_shares(
            dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
            verified_responses: &[Option<CLibVerifiedResponseBytes>],
        ) -> Result<
            Vec<Option<(EphemeralPublicKeyBytes, EncryptedShareBytes)>>,
            DkgCreateTranscriptError,
        > {
            verified_responses
                .iter()
                .enumerate()
                .map(|(receiver_index, response_maybe)| {
                    if let Some(verified_response) = response_maybe {
                        Ok(Some((
                            verified_response.receiver_public_key,
                            combined_receiver_share(dealings, receiver_index)?,
                        )))
                    } else {
                        Ok(None)
                    }
                })
                .collect()
        }

        /// Gets the share for one receiver from all dealings.
        fn combined_receiver_share(
            dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
            receiver_index: usize,
        ) -> Result<EncryptedShareBytes, DkgCreateTranscriptError> {
            // Collect the shares for one receiver:
            let shares: Result<Vec<EncryptedShare>, DkgCreateTranscriptError> = dealings
                .iter()
                .map(|(_dealer_public_key, dealing)| {
                    EncryptedShare::try_from(
                        dealing
                            .receiver_data
                            .get(receiver_index)
                            .ok_or_else(|| {
                                DkgCreateTranscriptError::MalformedDealingError(
                                    MalformedDataError {
                                        algorithm: AlgorithmId::Secp256k1,
                                        internal_error: "Receiver index out of range".to_string(),
                                        data: None,
                                    },
                                )
                            })?
                            .ok_or(DkgCreateTranscriptError::MalformedDealingError(
                                MalformedDataError {
                                    algorithm: AlgorithmId::Secp256k1,
                                    internal_error: "Missing share from dealer".to_string(),
                                    data: None,
                                },
                            ))?,
                    )
                    .map_err(|_| {
                        DkgCreateTranscriptError::MalformedDealingError(MalformedDataError {
                            algorithm: AlgorithmId::Secp256k1,
                            internal_error: "Malformed share".to_string(),
                            data: None,
                        })
                    })
                })
                .collect();
            let combined_share: EncryptedShare =
                shares?.iter().fold(EncryptedShare::zero(), |mut acc, x| {
                    acc.add_assign(x);
                    acc
                });
            Ok(EncryptedShareBytes::from(combined_share))
        }
    }

    /// Methods used by the resharing DKG
    pub mod resharing {
        use super::*;

        #[allow(clippy::type_complexity)] // This refers to the returned tuple
        pub fn select_dealer_data(
            threshold: NumberOfNodes,
            verified_dealings: &BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>,
            verified_responses: &[Option<CLibVerifiedResponseBytes>],
            dealer_keys: &[Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>],
            resharing_public_coefficients: &PublicCoefficientsBytes,
        ) -> Result<
            (
                Vec<NodeIndex>,
                Vec<EphemeralPublicKeyBytes>,
                Vec<CLibDealing>,
            ),
            DkgCreateReshareTranscriptError,
        > {
            // Get and verify the resharing threshold:
            let resharing_threshold_size = resharing_public_coefficients.coefficients.len();
            if NodeIndex::try_from(resharing_threshold_size).is_err() {
                return Err(DkgCreateReshareTranscriptError::SizeError(SizeError {
                    message: "Resharing threshold too large".to_string(),
                }));
            }

            // Invalid dealings are removed as with the simple DKG:
            let dealings = transcript_util::get_valid_dealings(
                threshold,
                verified_dealings,
                verified_responses,
            )?;

            // We need just the first `resharing_threshold_size` dealings:
            let dealings_with_keys = (0_u32..).zip(dealer_keys).filter_map(|(index, key_maybe)| {
                key_maybe
                    .map(|key| dealings.get(&key.0).map(|dealing| (index, key.0, dealing)))
                    .flatten()
            });
            let first_n = dealings_with_keys.take(resharing_threshold_size);

            let mut selected_dealer_indices: Vec<NodeIndex> =
                Vec::with_capacity(resharing_threshold_size);
            let mut selected_dealer_public_keys: Vec<EphemeralPublicKeyBytes> =
                Vec::with_capacity(resharing_threshold_size);
            let mut selected_dealings: Vec<CLibDealing> =
                Vec::with_capacity(resharing_threshold_size);

            for (index, key, dealing) in first_n {
                let dealing = CLibDealing::try_from(dealing)
                    .map_err(DkgCreateReshareTranscriptError::MalformedDealingError)?;
                selected_dealer_indices.push(index);
                selected_dealer_public_keys.push(key);
                selected_dealings.push(dealing);
            }

            if selected_dealer_indices.len() != resharing_threshold_size {
                return Err(DkgCreateReshareTranscriptError::InsufficientDataError(
                    InvalidArgumentError {
                        message: "Insufficient dealings to preserve threshold key".to_string(),
                    },
                ));
            }

            Ok((
                selected_dealer_indices,
                selected_dealer_public_keys,
                selected_dealings,
            ))
        }

        /// Computes combined public coefficients and key shares
        pub fn combine_public_coefficients_and_receiver_shares(
            selected_dealer_indices: &[NodeIndex],
            selected_dealings: Vec<CLibDealing>,
            receiver_key_bytes: &[Option<EphemeralPublicKeyBytes>],
        ) -> (PublicCoefficients, Vec<Option<EncryptedShare>>) {
            // The Lagrange coefficients are factors used when combining:
            let lagrange_coefficients = {
                let reshare_x: Vec<ThresholdSecretKey> = selected_dealer_indices
                    .iter()
                    .copied()
                    .map(x_for_index)
                    .collect();

                PublicCoefficients::lagrange_coefficients_at_zero(&reshare_x)
                    .expect("Cannot fail because all x are distinct.")
            };

            // Initial values:
            let mut public_coefficients = PublicCoefficients::zero();
            let mut receiver_data: Vec<Option<EncryptedShare>> = receiver_key_bytes
                .iter()
                .map(|key_maybe| key_maybe.as_ref().map(|_| EncryptedShare::zero()))
                .collect();

            // Combine:
            for (dealing, factor) in selected_dealings.into_iter().zip(lagrange_coefficients) {
                // Aggregate the public coefficients:
                public_coefficients += dealing.public_coefficients * factor;

                // Aggregate the ciphertexts:
                for (accumulator, next) in receiver_data.iter_mut().zip(&dealing.receiver_data) {
                    if let (Some(accumulated_receiver_data), Some(dealing_receiver_data)) =
                        (accumulator.as_mut(), next.as_ref())
                    {
                        accumulated_receiver_data.add_assign(&{
                            let mut x = *dealing_receiver_data;
                            x.mul_assign(&factor);
                            x
                        })
                    }
                }
            }
            (public_coefficients, receiver_data)
        }
    }
}

/// Computes a receiver's threshold secret key.
///
/// # Arguments
/// * `receiver_secret_key` - the receiver's secret key, used to decrypt the
///   threshold key.
/// * `transcript` - contains all the threshold keys, including the public
///   coefficients and (encrypted) secret keys.
/// * `dkg_id` - the key distribution ID, needed when decrypting the threshold
///   key as the `IDkgId` is not in the transcript.
/// # Returns
/// Returns the threshold secret key, if one was issued for this node, and None
/// otherwise.
/// # Panics
/// This method is not expected to panic.
/// # Errors
/// This method MUST return an error if:
/// * any of the arguments is malformed.
/// * the computed secret threshold key is not consistent with the public
///   coefficients.
pub fn compute_private_key(
    receiver_secret_key_bytes: EphemeralSecretKeyBytes,
    transcript: &CLibTranscriptBytes,
    dkg_id: IDkgId,
) -> Result<Option<ThresholdSecretKeyBytes>, DkgLoadPrivateKeyError> {
    let receiver_secret_key = EphemeralSecretKey::try_from(receiver_secret_key_bytes)
        .map_err(DkgLoadPrivateKeyError::MalformedSecretKeyError)?;
    let receiver_public_key = EphemeralPublicKey::from(&receiver_secret_key);
    let receiver_public_key_bytes: EphemeralPublicKeyBytes = receiver_public_key.clone().into();

    let record_maybe: Option<(NodeIndex, EncryptedShareBytes)> =
        transcript.get_receiver_data(receiver_public_key_bytes);

    if let Some((receiver_index, encrypted_share_bytes)) = record_maybe {
        let dealer_public_keys: Vec<EphemeralPublicKey> = {
            let parsed: Result<Vec<_>, _> = transcript
                .dealer_public_keys
                .iter()
                .map(|dealer_public_key_bytes| {
                    EphemeralPublicKey::try_from(dealer_public_key_bytes)
                        .map_err(|e| DkgLoadPrivateKeyError::MalformedTranscriptError(e.into()))
                })
                .collect();
            parsed?
        };
        let encryption_keys = dealer_public_keys.iter().map(|dealer_public_key| {
            let diffie_hellman = dealer_public_key.clone() * &receiver_secret_key;
            key_encryption_key(
                dkg_id,
                dealer_public_key,
                receiver_public_key.clone(),
                diffie_hellman,
            )
        });
        let share: ThresholdSecretKey = {
            let mut share = EncryptedShare::try_from(encrypted_share_bytes)
                .map_err(DkgLoadPrivateKeyError::MalformedTranscriptError)?;
            if let Some(dealer_reshare_indices) = &transcript.dealer_reshare_indices {
                let dealer_reshare_x: Vec<ThresholdSecretKey> = dealer_reshare_indices
                    .iter()
                    .map(|index| x_for_index(*index))
                    .collect();
                let lagrange_coefficients: Vec<ThresholdSecretKey> =
                    PublicCoefficients::lagrange_coefficients_at_zero(&dealer_reshare_x)
                        .expect("cannot fail");
                for key_encryption_key in
                    encryption_keys
                        .zip(&lagrange_coefficients)
                        .map(|(mut key, coefficient)| {
                            key.mul_assign(coefficient);
                            key
                        })
                {
                    share.sub_assign(&key_encryption_key);
                }
            } else {
                for key_encryption_key in encryption_keys {
                    share.sub_assign(&key_encryption_key);
                }
            }
            share
        };
        let public_coefficients: PublicCoefficients =
            PublicCoefficients::try_from(&transcript.public_coefficients).map_err(|_| {
                DkgLoadPrivateKeyError::MalformedTranscriptError(MalformedDataError {
                    algorithm: AlgorithmId::Secp256k1, /* Note: This is the algorithm of the
                                                        * method rather than of the type, which
                                                        * is Bls12_381. */
                    internal_error: "Could not parse public coefficients".to_string(),
                    data: None,
                })
            })?;
        if !secret_key_is_consistent(share, &public_coefficients, receiver_index) {
            return Err(DkgLoadPrivateKeyError::InvalidTranscriptError(
                InvalidArgumentError {
                    message: "Cannot reconstruct secret".to_string(),
                },
            ));
        }

        Ok(Some(ThresholdSecretKeyBytes::from(share))) // Return threshold
                                                       // secret key
    } else {
        Ok(None) // This receiver is not participating.
    }
}
