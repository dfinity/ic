use super::*;
pub use crate::sign::threshold_sig::store::ThresholdSigDataStore;
pub use crate::sign::threshold_sig::store::ThresholdSigDataStoreImpl;
use crate::sign::threshold_sig::store::TranscriptData;
use ic_crypto_internal_csp::api::{CspThresholdSignError, ThresholdSignatureCspClient};
use ic_crypto_internal_csp::types::CspPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_key::CspThresholdSigPublicKey;
use ic_registry_client::helper::crypto::CryptoRegistry;
use ic_types::crypto::threshold_sig::errors::threshold_sig_data_not_found_error::ThresholdSigDataNotFoundError;
use ic_types::crypto::threshold_sig::ni_dkg::{DkgId, NiDkgTag, NiDkgTranscript};
use ic_types::crypto::{CombinedThresholdSigOf, ThresholdSigShareOf};
use ic_types::{NodeIndex, SubnetId};
use std::cmp;

mod ni_dkg;
mod store;

#[cfg(test)]
mod tests;

pub struct ThresholdSignerInternal {}

impl ThresholdSignerInternal {
    pub fn sign_threshold<C: ThresholdSignatureCspClient, H: Signable>(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        threshold_sig_csp_client: &C,
        message: &H,
        dkg_id: DkgId,
    ) -> Result<ThresholdSigShareOf<H>, ThresholdSignError> {
        let pub_coeffs = pub_coeffs_from_store(dkg_id, lockable_threshold_sig_data_store)?;
        let csp_signature = threshold_sig_csp_client
            .threshold_sign(
                AlgorithmId::from(&pub_coeffs),
                message.as_signed_bytes().as_slice(),
                pub_coeffs,
            )
            .map_err(|error| map_threshold_sign_error_or_panic(error, dkg_id))?;
        threshold_sig_share_or_panic(csp_signature)
    }
}

// Use this if only the pub coeffs are needed from the store. If also indices
// are required, use transcript_data_from_store instead.
fn pub_coeffs_from_store(
    dkg_id: DkgId,
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
) -> Result<CspPublicCoefficients, ThresholdSigDataNotFoundError> {
    lockable_threshold_sig_data_store
        .read()
        .transcript_data(dkg_id)
        .map(|data| data.public_coefficients().clone())
        .ok_or(ThresholdSigDataNotFoundError::ThresholdSigDataNotFound { dkg_id })
}

fn transcript_data_from_store(
    dkg_id: DkgId,
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
) -> Result<TranscriptData, ThresholdSigDataNotFoundError> {
    lockable_threshold_sig_data_store
        .read()
        .transcript_data(dkg_id)
        .cloned()
        .ok_or_else(|| sig_data_not_found_error(dkg_id))
}

fn sig_data_not_found_error(dkg_id: DkgId) -> ThresholdSigDataNotFoundError {
    ThresholdSigDataNotFoundError::ThresholdSigDataNotFound { dkg_id }
}

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
    dkg_id: DkgId,
) -> ThresholdSignError {
    match error {
        CspThresholdSignError::SecretKeyNotFound { algorithm, key_id } => {
            // If the secret key was not found, reloading the transcript will not help
            // because we are sure at this point that the transcript was already
            // successfully loaded. Thus, we don't return a ThresholdSigDataNotFound error
            // here.
            ThresholdSignError::SecretKeyNotFound {
                dkg_id,
                algorithm,
                key_id,
            }
        }
        // Panic, since these would be implementation errors:
        CspThresholdSignError::UnsupportedAlgorithm { .. }
        | CspThresholdSignError::MalformedSecretKey { .. }
        | CspThresholdSignError::WrongSecretKeyType { .. } => panic!("Illegal state: {}", error),
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
        dkg_id: DkgId,
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
/// Given that both cases indicate that the implementations of DKG and threshold
/// signatures are not aligned and also a caller could not recover from this, we
/// panic.
fn lazily_calculated_public_key_from_store<C: ThresholdSignatureCspClient>(
    lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
    threshold_sig_csp_client: &C,
    dkg_id: DkgId,
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
    dkg_id: DkgId,
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
    dkg_id: DkgId,
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
                "Calculation of individual threshold public key for DKG ID {:?} \
                for node ID {} failed because the threshold signature data \
                store contained malformed data: {:?}",
                dkg_id, node_id, error
            )
        });
    lockable_threshold_sig_data_store
        .write()
        .insert_individual_public_key(dkg_id, node_id, public_key);
    Ok(public_key)
}

fn coeffs_and_index(
    transcript_data: TranscriptData,
    dkg_id: DkgId,
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
            not supported: {}",
            error
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
        dkg_id: DkgId,
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
            .map_err(map_csp_combine_sigs_error_or_panic)?;
        combined_threshold_sig_or_panic(csp_signature)
    }
}

fn shares_to_vector<H: Signable>(
    transcript_data: &TranscriptData,
    shares: BTreeMap<NodeId, ThresholdSigShareOf<H>>,
    dkg_id: DkgId,
) -> CryptoResult<Vec<Option<CspSignature>>> {
    let max_node_index = maximum_node_index(transcript_data, &shares, dkg_id)?;
    let array_size = <usize>::try_from(max_node_index).expect("usize overflow") + 1;
    let mut signatures = vec![None; array_size];
    for (node_id, share) in shares {
        let index = index_for_node_id(transcript_data, node_id, dkg_id)?;
        let usize_index = <usize>::try_from(index).expect("usize overflow");
        let csp_sig = CspSignature::try_from(&share)?;
        *signatures.get_mut(usize_index).unwrap() = Some(csp_sig);
    }
    Ok(signatures)
}

fn maximum_node_index<H: Signable>(
    transcript_data: &TranscriptData,
    shares: &BTreeMap<NodeId, ThresholdSigShareOf<H>>,
    dkg_id: DkgId,
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
    dkg_id: DkgId,
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

// TODO (DFN-1505): improve the error handling by introducing more specific
// errors on CSP level.
fn map_csp_combine_sigs_error_or_panic(error: CryptoError) -> CryptoError {
    match error {
        // TODO (DFN-1505): InvalidArgument is returned in these cases:
        // - threshold too high -> Error must be forwarded to the caller (as is the case now)
        // - error reading coeffs / unknown algorithm -> should lead to a panic (illegal state).
        //   This is not the case now!
        CryptoError::MalformedSignature { .. } | CryptoError::InvalidArgument { .. } => error,
        _ => panic!("Illegal state: unexpected error from the CSP: {}", error),
    }
}

fn node_id_missing_error(node_id: NodeId, dkg_id: DkgId) -> CryptoError {
    CryptoError::InvalidArgument {
        message: format!(
            "There is no node index for dkg id \"{:?}\" and node id \"{}\" in the transcript data.",
            dkg_id, node_id
        ),
    }
}

impl ThresholdSigVerifierInternal {
    pub fn verify_threshold_sig_combined<C: ThresholdSignatureCspClient, H: Signable>(
        lockable_threshold_sig_data_store: &LockableThresholdSigDataStore,
        threshold_sig_csp_client: &C,
        signature: &CombinedThresholdSigOf<H>,
        message: &H,
        dkg_id: DkgId,
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
            .map_err(map_verify_combined_error_or_panic)
    }
}

// TODO (DFN-1186): improve the error handling by introducing more specific
// errors on CSP level.
fn map_verify_combined_error_or_panic(error: CryptoError) -> CryptoError {
    match error {
        CryptoError::SignatureVerification { .. } | CryptoError::MalformedSignature { .. } => error,
        CryptoError::InvalidArgument { .. } => {
            panic!("Illegal state: unsupported algorithm: {}", error)
        }
        CryptoError::MalformedPublicKey { .. } => panic!(
            "Illegal state: the public key computed from the public coefficients \
                is malformed: {}",
            error
        ),
        _ => panic!("Illegal state: unexpected error from the CSP: {}", error),
    }
}

impl ThresholdSigVerifierInternal {
    pub fn verify_combined_threshold_sig_by_public_key<C, H>(
        threshold_sig_csp_client: &C,
        registry: Arc<dyn RegistryClient>,
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
        let transcript = initial_ni_dkg_transcript_from_registry(
            registry,
            subnet_id,
            version,
            NiDkgTag::HighThreshold,
        )?;
        let csp_pub_coeffs = CspPublicCoefficients::from(&transcript);
        threshold_sig_csp_client
            .threshold_verify_combined_signature(
                AlgorithmId::from(&csp_pub_coeffs),
                message.as_signed_bytes().as_slice(),
                csp_signature,
                csp_pub_coeffs,
            )
            .map_err(map_verify_combined_error_or_panic)
    }
}

fn initial_ni_dkg_transcript_from_registry(
    registry: Arc<dyn RegistryClient>,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    dkg_tag: NiDkgTag,
) -> CryptoResult<NiDkgTranscript> {
    let maybe_transcripts = registry
        .get_initial_dkg_transcripts(subnet_id, registry_version)
        .map_err(CryptoError::RegistryClient)?;
    match maybe_transcripts.value {
        Some(transcripts) => Ok(match dkg_tag {
            NiDkgTag::LowThreshold => transcripts.low_threshold,
            NiDkgTag::HighThreshold => transcripts.high_threshold,
        }),
        None => Err(CryptoError::DkgTranscriptNotFound {
            subnet_id,
            registry_version,
        }),
    }
}
