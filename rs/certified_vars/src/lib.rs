use ic_crypto_tree_hash::LabeledTree;
use ic_crypto_utils_threshold_sig::verify_combined;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{
        threshold_sig::ThresholdSigPublicKey, CombinedThresholdSig, CombinedThresholdSigOf,
        CryptoHash,
    },
    messages::{Blob, Certificate},
    CanisterId, CryptoHashOfPartialState, Time,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use tree_deserializer::{types::Leb128EncodedU64, LabeledTreeDeserializer};

/// Describes an error that occurred during parsing and validation of the result
/// of a `RegistryCanister::get_certified_changes_since()` method call.
#[derive(Debug)]
pub enum CertificateValidationError {
    /// Failed to deserialize some part of the certificate.
    DeserError(String),
    /// Signature verification failed.
    InvalidSignature(String),
    /// The value at path `/canister/<cid>/certified_data` does not match the
    /// hash computed from the mixed hash tree with registry deltas.
    CertifiedDataMismatch {
        certified: Vec<u8>,
        computed: Vec<u8>,
    },
    /// The hash tree in the response was not well-formed.
    MalformedHashTree(String),
    /// The certification contains a subnet delegation, which is not allowed for
    /// certificates coming from the root subnet.
    SubnetDelegationNotAllowed,
}

impl fmt::Display for CertificateValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeserError(err) => write!(f, "failed to deserialize certificate: {}", err),
            Self::InvalidSignature(err) => {
                write!(f, "failed to verify threshold signature: {}", err)
            }
            Self::CertifiedDataMismatch {
                certified,
                computed,
            } => write!(
                f,
                "certified data values do not match: certificate value is {}, tree hash is {}",
                hex::encode(&certified[..]),
                hex::encode(&computed[..])
            ),

            Self::MalformedHashTree(err) => write!(f, "hash tree in not well-formed: {}", err),
            Self::SubnetDelegationNotAllowed => write!(
                f,
                "expected certificate from the root subnet but found delegations in the certificate"
            ),
        }
    }
}

/// Checks if the specified certificate verifies the certified data of
/// specified canister.
///
/// If the check is successful, this function returns the timestamp on the
/// certificate.
pub fn verify_certificate(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
    certified_data: &[u8],
) -> Result<Time, CertificateValidationError> {
    #[derive(Deserialize)]
    struct CanisterView {
        certified_data: Blob,
    }

    #[derive(Deserialize)]
    struct ReplicaState {
        time: Leb128EncodedU64,
        canister: BTreeMap<CanisterId, CanisterView>,
    }

    let certificate: Certificate = serde_cbor::from_slice(certificate).map_err(|err| {
        CertificateValidationError::DeserError(format!(
            "failed to decode certificate from canister {}: {}",
            canister_id, err
        ))
    })?;

    if certificate.delegation.is_some() {
        return Err(CertificateValidationError::SubnetDelegationNotAllowed);
    }

    let digest = CryptoHashOfPartialState::from(CryptoHash(certificate.tree.digest().to_vec()));
    let content = CertificationContent::new(digest.clone());
    let sig = CombinedThresholdSigOf::new(CombinedThresholdSig(certificate.signature.to_vec()));
    verify_combined(&content, &sig, root_pk).map_err(|err| {
        CertificateValidationError::InvalidSignature(format!(
            "root_hash={:?}, sig={:?}, pk={:?}, error={:?}",
            digest, certificate.signature, root_pk, err
        ))
    })?;

    let replica_labeled_tree =
        LabeledTree::<Vec<u8>>::try_from(certificate.tree).map_err(|err| {
            CertificateValidationError::MalformedHashTree(format!(
                "failed to convert hash tree to labeled tree: {:?}",
                err
            ))
        })?;

    let replica_state = ReplicaState::deserialize(LabeledTreeDeserializer::new(
        &replica_labeled_tree,
    ))
    .map_err(|err| {
        CertificateValidationError::DeserError(format!(
            "failed to unpack replica state from a labeled tree: {}",
            err
        ))
    })?;

    let time = Time::from_nanos_since_unix_epoch(replica_state.time.0);

    let certificate_certified_data = replica_state
        .canister
        .get(canister_id)
        .map(|canister| canister.certified_data.clone())
        .ok_or_else(|| {
            CertificateValidationError::MalformedHashTree(format!(
                "cannot find certified_data for canister {} in the tree",
                canister_id
            ))
        })?;

    if certified_data != certificate_certified_data.0.as_slice() {
        return Err(CertificateValidationError::CertifiedDataMismatch {
            certified: certificate_certified_data.0,
            computed: certified_data.to_vec(),
        });
    }

    Ok(time)
}
