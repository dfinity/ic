//! Dealing phase of Groth20-BLS12-381 non-interactive distributed key
//! generation.

use super::encryption::{encrypt_and_prove, verify_zk_proofs};
use crate::api::ni_dkg_errors::{
    CspDkgCreateDealingError, CspDkgCreateReshareDealingError, CspDkgVerifyDealingError,
    InvalidArgumentError, MalformedSecretKeyError, MisnumberedReceiverError, SizeError,
    dealing::InvalidDealingError,
};
use crate::{
    api::individual_public_key,
    crypto::{generate_threshold_key, threshold_share_secret_key},
};
use ic_crypto_internal_seed::Seed;
use ic_types::{NodeIndex, NumberOfNodes};
use std::collections::BTreeMap;
use std::convert::TryFrom;

// "Old style" CSP types, used for the threshold keys:
use crate::types::{SecretKey as ThresholdSecretKey, SecretKeyBytes as ThresholdSecretKeyBytes};

// "New style" internal types, used for the NiDKG:
use super::ALGORITHM_ID;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::{
    Dealing, FsEncryptionPublicKey, PublicCoefficientsBytes,
};

/// Creates a new dealing, i.e. generates fresh threshold keys.
///
/// # Arguments
/// * `keygen_seed` - randomness used to seed the PRNG for generating the
///   keys/shares. It must be treated as a secret.
/// * `encryption_seed` - randomness used to seed the PRNG for encrypting the
///   shares and proving their correctness. It must be treated as a secret.
/// * `threshold` - the minimum number of individual signatures that can be
///   combined into a valid threshold signature.
/// * `receiver_keys` - forward-secure encryption public keys of the receivers.
/// * `epoch` - forward-secure epoch under which the shares are encrypted.
/// * `dealer_index` - index of the dealer.
///
/// # Errors
/// * `CspDkgCreateDealingError::SizeError` if the length of
///   `receiver_keys` isn't supported.
/// * `CspDkgCreateDealingError::InvalidThresholdError` if the threshold
///   is either zero or greater than the number of receivers.
/// * `CspDkgCreateDealingError::MalformedFsPublicKeyError` if one of the
///   `receiver_keys` is malformed.
/// * `CspDkgCreateDealingError::MisnumberedReceiverError` if the
///   receiver indices are not `0..num_receivers-1 inclusive`.
///
/// # Panics:
/// * If key generation produces key shares with non-contiguous indices.
/// * If key generation produces key shares that don't match the given
///   `receiver_keys`.
/// * If the key generation produces public coefficients that are malformed.
pub fn create_dealing(
    keygen_seed: Seed,
    encryption_seed: Seed,
    threshold: NumberOfNodes,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    epoch: Epoch,
    dealer_index: NodeIndex,
) -> Result<Dealing, CspDkgCreateDealingError> {
    let number_of_receivers =
        number_of_receivers(receiver_keys).map_err(CspDkgCreateDealingError::SizeError)?;

    // Check parameters
    {
        verify_threshold(threshold, number_of_receivers)
            .map_err(CspDkgCreateDealingError::InvalidThresholdError)?;
        verify_receiver_indices(receiver_keys, number_of_receivers).map_err(|e| {
            CspDkgCreateDealingError::MisnumberedReceiverError {
                receiver_index: e.receiver_index,
                number_of_receivers: e.number_of_receivers,
            }
        })?;
    }

    let (public_coefficients, threshold_secret_key_shares) =
        generate_threshold_key(keygen_seed, threshold, number_of_receivers)
            .map_err(CspDkgCreateDealingError::InvalidThresholdError)?;

    let public_coefficients = PublicCoefficientsBytes::from(&public_coefficients); // Internal to CSP type conversion

    let (ciphertexts, zk_proof_decryptability, zk_proof_correct_sharing) = {
        let key_message_pairs: Vec<_> = (0..)
            .zip(&threshold_secret_key_shares)
            .map(|(index, share)| {
                let share = share.clone();
                let key = *receiver_keys
                    .get(&index)
                    .expect("There should be a public key for each share");
                (key, share)
            })
            .collect();
        encrypt_and_prove(
            encryption_seed,
            &key_message_pairs,
            epoch,
            &public_coefficients,
            &dealer_index.to_be_bytes(),
        )
    }?;

    let dealing = Dealing {
        public_coefficients,
        ciphertexts,
        zk_proof_decryptability,
        zk_proof_correct_sharing,
    };
    Ok(dealing)
}

/// Creates a new dealing by resharing an existing secret key.
///
/// # Arguments
/// * `keygen_seed` - randomness used to seed the PRNG for generating the
///   keys/shares. It must be treated as a secret.
/// * `encryption_seed` - randomness used to seed the PRNG for encrypting the
///   shares and proving their correctness. It must be treated as a secret.
/// * `threshold` - the minimum number of individual signatures that can be
///   combined into a valid threshold signature.
/// * `receiver_keys` - forward-secure encryption public keys of the receivers.
/// * `epoch` - forward-secure epoch under which the shares are encrypted.
/// * `dealer_index` - index of the dealer.
/// * `resharing_secret` - existing secret key to reshare.
///
/// # Errors
/// * `CspDkgCreateReshareDealingError::SizeError` if the length of
///   `receiver_keys` isn't supported.
/// * `CspDkgCreateReshareDealingError::InvalidThresholdError` if the threshold
///   is either zero or greater than the number of receivers.
/// * `CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError` if
///   `resharing_secret` is malformed.
/// * `CspDkgCreateReshareDealingError::MalformedFsPublicKeyError` if one of the
///   `receiver_keys` is malformed.
/// * `CspDkgCreateReshareDealingError::MisnumberedReceiverError` if the
///   receiver indices are not `0..num_receivers-1 inclusive`.
///
/// # Panics:
/// * If key generation produces key shares with non-contiguous indices.
/// * If key generation produces key shares that don't match the given
///   `receiver_keys`.
/// * If the key generation produces public coefficients that are malformed.
pub fn create_resharing_dealing(
    keygen_seed: Seed,
    encryption_seed: Seed,
    threshold: NumberOfNodes,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    epoch: Epoch,
    dealer_index: NodeIndex,
    resharing_secret: ThresholdSecretKeyBytes,
) -> Result<Dealing, CspDkgCreateReshareDealingError> {
    let number_of_receivers =
        number_of_receivers(receiver_keys).map_err(CspDkgCreateReshareDealingError::SizeError)?;

    // Check parameters
    {
        verify_threshold(threshold, number_of_receivers)
            .map_err(CspDkgCreateReshareDealingError::InvalidThresholdError)?;
        verify_receiver_indices(receiver_keys, number_of_receivers)?;
    }

    let resharing_secret = ThresholdSecretKey::try_from(&resharing_secret).map_err(|_| {
        CspDkgCreateReshareDealingError::MalformedReshareSecretKeyError(MalformedSecretKeyError {
            algorithm: ALGORITHM_ID,
            internal_error: "Malformed reshared secret key".to_string(),
        })
    })?;

    let (public_coefficients, threshold_secret_key_shares) = threshold_share_secret_key(
        keygen_seed,
        threshold,
        number_of_receivers,
        &resharing_secret,
    )
    .map_err(CspDkgCreateReshareDealingError::InvalidThresholdError)?;

    let public_coefficients = PublicCoefficientsBytes::from(&public_coefficients); // Internal to CSP type conversion

    let (ciphertexts, zk_proof_decryptability, zk_proof_correct_sharing) = {
        let key_message_pairs: Vec<_> = (0..)
            .zip(&threshold_secret_key_shares)
            .map(|(index, share)| {
                let share = share.clone();
                let key = *receiver_keys
                    .get(&index)
                    .expect("There should be a public key for each share");
                (key, share)
            })
            .collect();
        encrypt_and_prove(
            encryption_seed,
            &key_message_pairs,
            epoch,
            &public_coefficients,
            &dealer_index.to_be_bytes(),
        )
    }?;

    let dealing = Dealing {
        public_coefficients,
        ciphertexts,
        zk_proof_decryptability,
        zk_proof_correct_sharing,
    };
    Ok(dealing)
}

/// Verifies a dealing.
///
/// # Arguments
/// * `dealer_index` - The index of the dealer that provided the given
///   `dealing`.
/// * `threshold` - The threshold required by the given `dealing`.
/// * `epoch` - The forward-secure encryption epoch used to encrypt the
///   receivers' shares.
/// * `receiver_keys` - The forward-secure encryption public keys used to
///   encrypt the receivers' shares.
/// * `dealing` - The dealing to verify.
///
/// # Errors
/// * `CspDkgVerifyDealingError::InvalidThresholdError` if the threshold is less
///   than 1.
/// * `CspDkgVerifyDealingError::InvalidThresholdError` if the threshold is
///   greater than the number of receivers.
/// * `MisnumberedReceiverError` if the receiver indices are not
///   0..num_receivers-1 inclusive.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if
///   - The share indices are not 0..num_receivers-1 inclusive.
///   - Any shares are malformed.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if
///   dealing.public_coefficients.len() != threshold.
/// * `CspDkgVerifyDealingError::MalformedDealingError` if any component of
///   `dealing` is malformed or invalid.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if any one of the
///   decryptability or sharing proofs of the dealing, or the integrity of the
///   dealing ciphertexts, don't verify.
pub fn verify_dealing(
    dealer_index: NodeIndex,
    threshold: NumberOfNodes,
    epoch: Epoch,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    dealing: &Dealing,
) -> Result<(), CspDkgVerifyDealingError> {
    let number_of_receivers =
        number_of_receivers(receiver_keys).map_err(CspDkgVerifyDealingError::SizeError)?;
    verify_threshold(threshold, number_of_receivers)
        .map_err(CspDkgVerifyDealingError::InvalidThresholdError)?;
    verify_receiver_indices(receiver_keys, number_of_receivers)?;
    verify_all_shares_are_present_and_well_formatted(dealing, number_of_receivers)
        .map_err(CspDkgVerifyDealingError::InvalidDealingError)?;
    verify_public_coefficients_match_threshold(dealing, threshold)
        .map_err(CspDkgVerifyDealingError::InvalidDealingError)?;
    verify_zk_proofs(
        epoch,
        receiver_keys,
        &dealing.public_coefficients,
        &dealing.ciphertexts,
        &dealing.zk_proof_decryptability,
        &dealing.zk_proof_correct_sharing,
        &dealer_index.to_be_bytes(),
    )?;
    Ok(())
}

/// Verifies a dealing created to reshare an existing secret.
///
/// Also cf. `verify_dealing`.
///
/// # Arguments
/// * `dealer_resharing_index` - The index of the dealer that provided the given
///   `dealing`.
/// * `threshold` - The threshold required by the given `dealing`.
/// * `epoch` - The forward-secure encryption epoch used to encrypt the
///   receivers' shares.
/// * `receiver_keys` - The forward-secure encryption public keys used to
///   encrypt the receivers' shares.
/// * `dealing` - The dealing to verify.
/// * `resharing_public_coefficients` - The `PublicCoefficients` corresponding
///   to the secret share that is being re-shared.
///
/// # Errors
/// * Same errors as `verify_dealing`.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if the constant term in
///   the public coefficient doesn't equal the individual public key of the
///   dealer in the resharing instance.
/// * `CspDkgVerifyDealingError::InvalidDealingError` if the dealer's public key
///   is malformed.
///
/// # Panics
/// * If there are no `public_coefficients` in `dealing`.
pub fn verify_resharing_dealing(
    dealer_resharing_index: NodeIndex,
    threshold: NumberOfNodes,
    epoch: Epoch,
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    dealing: &Dealing,
    resharing_public_coefficients: &PublicCoefficientsBytes,
) -> Result<(), CspDkgVerifyDealingError> {
    verify_dealing(
        dealer_resharing_index,
        threshold,
        epoch,
        receiver_keys,
        dealing,
    )?;

    // Check the constant term in the public coefficient corresponds to the
    // individual public key of the dealer in the resharing instance
    let dealt_public_key = dealing
        .public_coefficients
        .coefficients
        .first()
        .expect("verify_dealing guarantees that public_coefficients.len() == threshold > 0");
    let reshared_public_key =
        individual_public_key(resharing_public_coefficients, dealer_resharing_index).map_err(
            |error| {
                let error = InvalidArgumentError {
                    message: format!("{error}"),
                };
                CspDkgVerifyDealingError::InvalidDealingError(error)
            },
        )?;
    if *dealt_public_key != reshared_public_key {
        let error = InvalidDealingError::ReshareMismatch {
            old: reshared_public_key,
            new: *dealt_public_key,
        };
        let error = InvalidArgumentError::from(error);
        return Err(CspDkgVerifyDealingError::InvalidDealingError(error));
    }

    Ok(())
}

/// Tries to get the number of receivers as NumberOfNodes
fn number_of_receivers(
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
) -> Result<NumberOfNodes, SizeError> {
    let size = NodeIndex::try_from(receiver_keys.len()).map_err(|_| SizeError {
        message: format!(
            "Unsupported number of receivers:\n  Num receivers: {}\n  Max: {}",
            receiver_keys.len(),
            NodeIndex::MAX
        ),
    })?;
    Ok(NumberOfNodes::from(size))
}

/// Verifies that the threshold is at least 1 but not greater than the number of
/// receivers.
///
/// # Errors
/// * `InvalidArgumentError` if the threshold is less than 1.
/// * `InvalidArgumentError` if the threshold is greater than the number of
///   receivers.
pub fn verify_threshold(
    threshold: NumberOfNodes,
    number_of_receivers: NumberOfNodes,
) -> Result<(), InvalidArgumentError> {
    let min_threshold = NumberOfNodes::from(1);
    if threshold < min_threshold {
        return Err(InvalidArgumentError {
            message: format!(
                "Threshold to small:\n  Threshold: {threshold}\n  minimum: {min_threshold}"
            ),
        });
    }

    if threshold > number_of_receivers {
        return Err(InvalidArgumentError {
            message: format!(
                "Threshold to large:\n  Threshold: {threshold}\n  Number of receivers: {number_of_receivers}"
            ),
        });
    }
    Ok(())
}

/// Verifies that dealing.public_coefficients.len() == threshold.
pub fn verify_public_coefficients_match_threshold(
    dealing: &Dealing,
    threshold: NumberOfNodes,
) -> Result<(), InvalidArgumentError> {
    let public_coefficients_len =
        NodeIndex::try_from(dealing.public_coefficients.coefficients.len());
    if public_coefficients_len == Ok(threshold.get()) {
        Ok(())
    } else {
        let err = InvalidDealingError::ThresholdMismatch {
            threshold,
            public_coefficients_len: dealing.public_coefficients.coefficients.len(),
        };
        Err(InvalidArgumentError::from(err))
    }
}

/// Verifies that receivers are indexed correctly
///
/// # Errors
/// * `MisnumberedReceiverError` if the receiver indices are not
///   0..num_receivers-1 inclusive.
fn verify_receiver_indices(
    receiver_keys: &BTreeMap<NodeIndex, FsEncryptionPublicKey>,
    number_of_receivers: NumberOfNodes,
) -> Result<(), MisnumberedReceiverError> {
    // Verify that the receivers are indexed correctly:
    for receiver_index in receiver_keys.keys().copied() {
        if receiver_index >= number_of_receivers.get() {
            let error = MisnumberedReceiverError {
                receiver_index,
                number_of_receivers,
            };
            return Err(error);
        }
    }
    Ok(())
}

/// Verifies that shares are well formed and have the correct indices.
///
/// # Errors
/// * `InvalidArgumentError` if
///   - The share indices are not 0..num_receivers-1 inclusive.
///   - Any shares are malformed.
pub fn verify_all_shares_are_present_and_well_formatted(
    dealing: &Dealing,
    number_of_receivers: NumberOfNodes,
) -> Result<(), InvalidArgumentError> {
    // Check that all required indices are present:
    let num_encrypted_chunks = NodeIndex::try_from(dealing.ciphertexts.ciphertext_chunks.len());
    if num_encrypted_chunks != Ok(number_of_receivers.get()) {
        return Err(InvalidArgumentError {
            message: format!(
                "Incorrect number of shares.\n  Expected: {}\n  Got: {}",
                number_of_receivers.get(),
                dealing.ciphertexts.ciphertext_chunks.len()
            ),
        });
    }
    Ok(())
}
