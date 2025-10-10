use super::*;
pub use crate::sign::threshold_sig::store::ThresholdSigDataStore;
pub use crate::sign::threshold_sig::store::ThresholdSigDataStoreImpl;
use crate::sign::threshold_sig::store::TranscriptData;
use ic_crypto_internal_csp::api::{CspThresholdSignError, ThresholdSignatureCspClient};
use ic_crypto_internal_csp::types::CspPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_interfaces::crypto::ErrorReproducibility;
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_types::crypto::threshold_sig::errors::threshold_sig_data_not_found_error::ThresholdSigDataNotFoundError;
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTranscript};
use ic_types::crypto::{CombinedThresholdSigOf, ThresholdSigShareOf};
use ic_types::{NodeIndex, SubnetId};
use std::cmp;

mod ni_dkg;
mod store;

#[cfg(test)]
mod tests;

pub struct ThresholdSignerInternal {}

impl ThresholdSignerInternal {
    // TODO(CRP-2639): Adapt ThresholdSignError so that clippy exception is no longer needed
    #[allow(clippy::result_large_err)]
    pub fn sign_threshold<C: ThresholdSignatureCspClient, H: Signable>(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        threshold_sig_csp_client: &C,
        message: &H,
        dkg_id: &NiDkgId,
    ) -> Result<ThresholdSigShareOf<H>, ThresholdSignError> {
        let pub_coeffs = pub_coeffs_from_store(dkg_id, lockable_threshold_sig_data_store)?;
        let csp_signature = threshold_sig_csp_client
            .threshold_sign(
                AlgorithmId::from(&pub_coeffs),
                message.as_signed_bytes(),
                pub_coeffs,
            )
            .map_err(|error| map_threshold_sign_error_or_panic(error, dkg_id.clone()))?;
        threshold_sig_share_or_panic(csp_signature)
    }
}

// Use this if only the pub coeffs are needed from the store. If also indices
// are required, use transcript_data_from_store instead.
fn pub_coeffs_from_store(
    dkg_id: &NiDkgId,
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
) -> Result<CspPublicCoefficients, ThresholdSigDataNotFoundError> {
    let maybe_coeffs = lockable_threshold_sig_data_store
        .read()
        .transcript_data(dkg_id)
        .map(|data| data.public_coefficients().clone());
    maybe_coeffs.ok_or(ThresholdSigDataNotFoundError::ThresholdSigDataNotFound {
        dkg_id: dkg_id.clone(),
    })
}

fn transcript_data_from_store(
    dkg_id: &NiDkgId,
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
) -> Result<TranscriptData, ThresholdSigDataNotFoundError> {
    let maybe_transcript_data = lockable_threshold_sig_data_store
        .read()
        .transcript_data(dkg_id)
        .cloned();
    maybe_transcript_data.ok_or_else(|| sig_data_not_found_error(dkg_id.clone()))
}

fn sig_data_not_found_error(dkg_id: NiDkgId) -> ThresholdSigDataNotFoundError {
    ThresholdSigDataNotFoundError::ThresholdSigDataNotFound { dkg_id }
}

// TODO(CRP-2639): Adapt ThresholdSignError so that clippy exception is no longer needed
#[allow(clippy::result_large_err)]
fn threshold_sig_share_or_panic<H: Signable>(
    csp_signature: CspSignature,
) -> Result<ThresholdSigShareOf<H>, ThresholdSignError> {
    Ok(ThresholdSigShareOf::try_from(csp_signature).expect(
        "This case cannot occur because `CryptoError::MalformedSignature` is returned only \
            if the signature returned by the CSP is not a \
            `CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual)`, but this must \
            be guaranteed by the CSP.", /* TODO (DFN-1186) */
    ))
}

// Normally we implement a `From` conversion. But since this conversion takes
// the dkg_id as parameter, this cannot be done in this case.
fn map_threshold_sign_error_or_panic(
    error: CspThresholdSignError,
    dkg_id: NiDkgId,
) -> ThresholdSignError {
    match error {
        CspThresholdSignError::SecretKeyNotFound { algorithm, key_id } => {
            // If the secret key was not found, reloading the transcript will not generally help
            // because we are sure at this point that the transcript was already successfully
            // loaded. Thus a missing key indicates that the key was already removed. However,
            // if a call to `load_transcript`, which inserts a key in the secret key store,
            // runs concurrently with an invocation of `retain_active_keys`, which removes keys
            // associated with past epochs, it could happen that the inserted key is immediately
            // removed after insertion, even though it relates to a future epoch. In this case
            // calling again `load_transcript` may help reinserting the key in the key store.
            // Note that this is unexpected since consensus waits for past calls to
            // `retain_active_keys` to terminate before loading new transcripts.
            ThresholdSignError::SecretKeyNotFound {
                dkg_id,
                algorithm,
                key_id: key_id.to_string(),
            }
        }
        CspThresholdSignError::TransientInternalError { internal_error } => {
            ThresholdSignError::TransientInternalError { internal_error }
        }
        CspThresholdSignError::KeyIdInstantiationError(internal_error) => {
            ThresholdSignError::KeyIdInstantiationError(internal_error)
        }
        // Panic, since these would be implementation errors:
        CspThresholdSignError::UnsupportedAlgorithm { .. }
        | CspThresholdSignError::MalformedSecretKey { .. }
        | CspThresholdSignError::WrongSecretKeyType { .. } => {
            panic!("Illegal state: {error}")
        }
    }
}

pub struct ThresholdSigVerifierInternal {}

impl ThresholdSigVerifierInternal {
    /// # Panics
    /// * if the algorithm determined from the public key from the store (which
    ///   is based on the algorithm of the public coefficients in the store) is
    ///   not supported by  `csp.threshold_verify_individual_signature` (as
    ///   indicated by a `CryptoError::InvalidArgument` or
    ///   `CryptoError::MalformedPublicKey`)
    /// * if the signature provided to
    ///   `csp.threshold_verify_individual_signature` is not a
    ///   `CspSignature::ThresBls12_381(ThresBls12_381_Signature:: Individual)`
    ///   (as indicated by a `CryptoError::MalformedSignature`)`. This, however,
    ///   should never happen because the signature returned by
    ///   `CspSignature::try_from(ThresholdSigShareOf)` is always of this type.
    pub fn verify_threshold_sig_share<C: ThresholdSignatureCspClient, H: Signable>(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        threshold_sig_csp_client: &C,
        signature: &ThresholdSigShareOf<H>,
        message: &H,
        dkg_id: &NiDkgId,
        signer: NodeId,
    ) -> CryptoResult<()> {
        let csp_signature = CspSignature::try_from(signature)?;
        let public_key = lazily_calculated_public_key_from_store(
            lockable_threshold_sig_data_store,
            threshold_sig_csp_client,
            dkg_id,
            signer,
        )?;

        threshold_sig_csp_client
            .threshold_verify_individual_signature(
                AlgorithmId::from(public_key),
                message.as_signed_bytes().as_slice(),
                csp_signature,
                public_key,
            )
            .map_err(panic_on_illegal_individual_sig_verification_state)
    }
}

/// Returns the individual public key for the given `node_id` and `dkg_id` from
/// the store if present and otherwise calculates and stores it.
///
/// Note regarding concurrency: checking whether a public key is already
/// available in the store is done with a read lock while inserting a
/// key into the store is done with a write lock. This non-atomic approach
/// is intentional because we expect reads to happen more often and not
/// a problem because multiple threads would calculate and store the same key.
///
/// # Errors
/// * CryptoError::ThresholdSigDataNotFound if the public coefficients for
///   `dkg_id` are missing in the store
/// * CryptoError::ThresholdSigDataNotFound if the index for `node_id` for
///   `dkg_id` is missing in the store
///
/// # Panics
/// The method panics if calculating the individual public key fails. This
/// currently happens in the following two cases:
/// * the public coefficients are not of type `AlgorithmId::ThresBls12_381` (as
///   indicated by a `CryptoError::InvalidArgument`("unsupported algorithm"))
/// * conversion of the public coefficients to a BLS12-381 public key fails (as
///   indicated by a `CryptoError::MalformedPublicKey`("Invalid public key"))
///
/// Given that both cases indicate that the implementations of DKG and threshold
/// signatures are not aligned and also a caller could not recover from this, we
/// panic.
pub(crate) fn lazily_calculated_public_key_from_store<C: ThresholdSignatureCspClient>(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    threshold_sig_csp_client: &C,
    dkg_id: &NiDkgId,
    node_id: NodeId,
) -> CryptoResult<CspThresholdSigPublicKey> {
    match public_key_from_store(lockable_threshold_sig_data_store, dkg_id, node_id) {
        Some(public_key) => Ok(public_key),
        None => calculate_and_store_public_key_or_panic(
            lockable_threshold_sig_data_store,
            threshold_sig_csp_client,
            dkg_id,
            node_id,
        ),
    }
}

fn public_key_from_store(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    dkg_id: &NiDkgId,
    node_id: NodeId,
) -> Option<CspThresholdSigPublicKey> {
    lockable_threshold_sig_data_store
        .read()
        .individual_public_key(dkg_id, node_id)
        .cloned()
}

fn calculate_and_store_public_key_or_panic<C: ThresholdSignatureCspClient>(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    threshold_sig_csp_client: &C,
    dkg_id: &NiDkgId,
    node_id: NodeId,
) -> CryptoResult<CspThresholdSigPublicKey> {
    let transcript_data = transcript_data_from_store(dkg_id, lockable_threshold_sig_data_store)?;
    let (public_coeffs, node_index) = coeffs_and_index(transcript_data, dkg_id, node_id)?;
    let public_key = threshold_sig_csp_client
        .threshold_individual_public_key(
            AlgorithmId::from(&public_coeffs),
            node_index,
            public_coeffs,
        )
        .unwrap_or_else(|error| {
            panic!(
                "Calculation of individual threshold public key for DKG ID {dkg_id:?} \
                for node ID {node_id} failed because the threshold signature data \
                store contained malformed data: {error:?}"
            )
        });
    lockable_threshold_sig_data_store
        .write()
        .insert_individual_public_key(dkg_id, node_id, public_key);
    Ok(public_key)
}

fn coeffs_and_index(
    transcript_data: TranscriptData,
    dkg_id: &NiDkgId,
    node_id: NodeId,
) -> CryptoResult<(CspPublicCoefficients, NodeIndex)> {
    let public_coeffs = transcript_data.public_coefficients().clone();
    let node_index = transcript_data
        .index(node_id)
        .cloned()
        .ok_or_else(|| node_id_missing_error(node_id, dkg_id))?;
    Ok((public_coeffs, node_index))
}

fn panic_on_illegal_individual_sig_verification_state(error: CryptoError) -> CryptoError {
    match error {
        CryptoError::InvalidArgument { .. } | CryptoError::MalformedPublicKey { .. } => panic!(
            "Illegal state: the algorithm of the public key from the threshold signature data \
            store (which is based on the algorithm of the public coefficients in the store) is \
            not supported: {error}"
        ),
        CryptoError::MalformedSignature { .. } => unreachable!(
            "This case cannot occur because `CryptoError::MalformedSignature` is returned only \
            if the given signature was not a \
            `CspSignature::ThresBls12_381(ThresBls12_381_Signature::Individual)`, but we know \
            for sure that it has this type because this is the type returned by \
            `CspSignature::try_from(ThresholdSigShareOf)`." /* TODO (DFN-1186) */
        ),
        _ => error,
    }
}

impl ThresholdSigVerifierInternal {
    pub fn combine_threshold_sig_shares<C: ThresholdSignatureCspClient, H: Signable>(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        threshold_sig_csp_client: &C,
        shares: BTreeMap<NodeId, ThresholdSigShareOf<H>>,
        dkg_id: &NiDkgId,
    ) -> CryptoResult<CombinedThresholdSigOf<H>> {
        error_if_shares_empty(&shares)?;
        let transcript_data =
            transcript_data_from_store(dkg_id, lockable_threshold_sig_data_store)?;
        let public_coefficients = transcript_data.public_coefficients().clone();
        let csp_signature = threshold_sig_csp_client
            .threshold_combine_signatures(
                AlgorithmId::from(&public_coefficients),
                &shares_to_vector(&transcript_data, shares, dkg_id)?,
                public_coefficients,
            )
            .map_err(map_csp_combine_sigs_error)?;
        combined_threshold_sig_or_panic(csp_signature)
    }
}

fn shares_to_vector<H: Signable>(
    transcript_data: &TranscriptData,
    shares: BTreeMap<NodeId, ThresholdSigShareOf<H>>,
    dkg_id: &NiDkgId,
) -> CryptoResult<Vec<Option<CspSignature>>> {
    let max_node_index = maximum_node_index(transcript_data, &shares, dkg_id)?;
    let array_size = <usize>::try_from(max_node_index).expect("usize overflow") + 1;
    let mut signatures = vec![None; array_size];
    for (node_id, share) in shares {
        let index = index_for_node_id(transcript_data, node_id, dkg_id)?;
        let usize_index = <usize>::try_from(index).expect("usize overflow");
        let csp_sig = CspSignature::try_from(&share)?;
        *signatures
            .get_mut(usize_index)
            .expect("Index unexpectedly out of range") = Some(csp_sig);
    }
    Ok(signatures)
}

fn maximum_node_index<H: Signable>(
    transcript_data: &TranscriptData,
    shares: &BTreeMap<NodeId, ThresholdSigShareOf<H>>,
    dkg_id: &NiDkgId,
) -> CryptoResult<NodeIndex> {
    shares.iter().try_fold(0, |cur_max, (node_id, _share)| {
        index_for_node_id(transcript_data, *node_id, dkg_id).map(|index| cmp::max(cur_max, index))
    })
}

fn error_if_shares_empty<H: Signable>(
    shares: &BTreeMap<NodeId, ThresholdSigShareOf<H>>,
) -> CryptoResult<()> {
    if shares.is_empty() {
        return Err(CryptoError::InvalidArgument {
            message: "The shares must not be empty.".to_string(),
        });
    }
    Ok(())
}

fn index_for_node_id(
    transcript_data: &TranscriptData,
    node_id: NodeId,
    dkg_id: &NiDkgId,
) -> CryptoResult<NodeIndex> {
    transcript_data
        .index(node_id)
        .copied()
        .ok_or_else(|| node_id_missing_error(node_id, dkg_id))
}

fn combined_threshold_sig_or_panic<H: Signable>(
    csp_signature: CspSignature,
) -> CryptoResult<CombinedThresholdSigOf<H>> {
    Ok(CombinedThresholdSigOf::try_from(csp_signature).expect(
        "The CSP must return a signature of type \
        `CspSignature::ThresBls12_381(ThresBls12_381_Signature::Combined)`.", /* TODO (DFN-1186) */
    ))
}

fn map_csp_combine_sigs_error(error: CryptoError) -> CryptoError {
    match error {
        CryptoError::MalformedSignature { .. } | CryptoError::InvalidArgument { .. } => error,
        _ => {
            if error.is_reproducible() {
                CryptoError::InternalError {
                    internal_error: format!("Unexpected error from the CSP: {error}"),
                }
            } else {
                CryptoError::TransientInternalError {
                    internal_error: format!("Transient internal error: {error}"),
                }
            }
        }
    }
}

fn node_id_missing_error(node_id: NodeId, dkg_id: &NiDkgId) -> CryptoError {
    CryptoError::InvalidArgument {
        message: format!(
            "There is no node index for dkg id \"{dkg_id:?}\" and node id \"{node_id}\" in the transcript data."
        ),
    }
}

impl ThresholdSigVerifierInternal {
    pub fn verify_threshold_sig_combined<C: ThresholdSignatureCspClient, H: Signable>(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        threshold_sig_csp_client: &C,
        signature: &CombinedThresholdSigOf<H>,
        message: &H,
        dkg_id: &NiDkgId,
    ) -> CryptoResult<()> {
        let pub_coeffs = pub_coeffs_from_store(dkg_id, lockable_threshold_sig_data_store)?;
        let csp_signature = CspSignature::try_from(signature)?;
        threshold_sig_csp_client
            .threshold_verify_combined_signature(
                AlgorithmId::from(&pub_coeffs),
                message.as_signed_bytes().as_slice(),
                csp_signature,
                pub_coeffs,
            )
            .map_err(map_verify_combined_error)
    }
}

// TODO (DFN-1186): improve the error handling by introducing more specific
// errors on CSP level.
fn map_verify_combined_error(error: CryptoError) -> CryptoError {
    match error {
        CryptoError::SignatureVerification { .. }
        | CryptoError::MalformedSignature { .. }
        | CryptoError::InvalidArgument { .. }
        | CryptoError::MalformedPublicKey { .. } => error,
        _ => {
            if error.is_reproducible() {
                CryptoError::InternalError {
                    internal_error: format!("Unexpected error from the CSP: {error}"),
                }
            } else {
                CryptoError::TransientInternalError {
                    internal_error: format!("Transient internal error: {error}"),
                }
            }
        }
    }
}

impl ThresholdSigVerifierInternal {
    pub fn verify_combined_threshold_sig_by_public_key<C, H>(
        threshold_sig_csp_client: &C,
        registry: &dyn RegistryClient,
        signature: &CombinedThresholdSigOf<H>,
        message: &H,
        subnet_id: SubnetId,
        version: RegistryVersion,
    ) -> CryptoResult<()>
    where
        C: ThresholdSignatureCspClient,
        H: Signable,
    {
        let csp_signature = CspSignature::try_from(signature)?;
        let transcript =
            initial_high_threshold_ni_dkg_transcript_from_registry(registry, subnet_id, version)?;
        let csp_pub_coeffs = CspPublicCoefficients::from(&transcript);
        threshold_sig_csp_client
            .threshold_verify_combined_signature(
                AlgorithmId::from(&csp_pub_coeffs),
                message.as_signed_bytes().as_slice(),
                csp_signature,
                csp_pub_coeffs,
            )
            .map_err(map_verify_combined_error)
    }
}

fn initial_high_threshold_ni_dkg_transcript_from_registry(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> CryptoResult<NiDkgTranscript> {
    let maybe_transcripts = registry
        .get_initial_dkg_transcripts(subnet_id, registry_version)
        .map_err(CryptoError::RegistryClient)?;
    match maybe_transcripts.value {
        Some(transcripts) => Ok(transcripts.high_threshold),
        None => Err(CryptoError::DkgTranscriptNotFound {
            subnet_id,
            registry_version,
        }),
    }
}
