use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;

use serde::Deserialize;

use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_crypto_utils_threshold_sig::{parse_threshold_sig_key_from_der, verify_combined};
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{
        threshold_sig::ThresholdSigPublicKey, CombinedThresholdSig, CombinedThresholdSigOf,
        CryptoHash,
    },
    messages::{Blob, Certificate},
    CanisterId, CryptoHashOfPartialState, PrincipalId, SubnetId, Time,
};
use tree_deserializer::{types::Leb128EncodedU64, LabeledTreeDeserializer};

#[cfg(test)]
mod tests;

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
    /// The certification contains nested subnet delegations, which is currently not allowed for
    /// certificates.
    MultipleSubnetDelegationsNotAllowed,
    /// The given canister id is not contained in the ranges specified by the subnet delegation.
    CanisterIdOutOfRange,
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
            Self::MultipleSubnetDelegationsNotAllowed => write!(
                f,
                "expected certificate with a maximum of one delegations but found nested delegations in the certificate"
            ),
            Self::CanisterIdOutOfRange => {
                write!(
                    f,
                    "canister id does not match the canister id range specified in the certificate"
                )
            }
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
    #[derive(Deserialize, Debug)]
    struct CanisterView {
        certified_data: Blob,
    }

    #[derive(Deserialize, Debug)]
    struct ReplicaState {
        time: Leb128EncodedU64,
        canister: BTreeMap<CanisterId, CanisterView>,
    }

    let certificate: Certificate = parse_certificate(certificate)?;

    let key = if let Some(delegation) = &certificate.delegation {
        let subnet_id = PrincipalId::try_from(&*delegation.subnet_id)
            .map(SubnetId::from)
            .map_err(|err| {
                CertificateValidationError::DeserError(format!(
                    "failed to parse delegation subnet id: {}",
                    err
                ))
            })?;
        verify_delegation_certificate(&delegation.certificate, &subnet_id, root_pk, canister_id)?
    } else {
        *root_pk
    };

    verify_certificate_signature(&certificate, &key)?;

    let replica_labeled_tree = parse_tree(certificate.tree)?;
    let replica_state = ReplicaState::deserialize(LabeledTreeDeserializer::new(
        &replica_labeled_tree,
    ))
    .map_err(|err| {
        CertificateValidationError::DeserError(format!(
            "failed to unpack replica state from a labeled tree: {}",
            err
        ))
    })?;

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

    Ok(Time::from_nanos_since_unix_epoch(replica_state.time.0))
}

fn verify_delegation_certificate(
    certificate: &[u8],
    subnet_id: &SubnetId,
    root_pk: &ThresholdSigPublicKey,
    canister_id: &CanisterId,
) -> Result<ThresholdSigPublicKey, CertificateValidationError> {
    #[derive(Deserialize, Debug)]
    struct SubnetView {
        canister_ranges: Blob,
        public_key: Blob,
    }

    #[derive(Deserialize, Debug)]
    struct SubnetCertificateData {
        #[allow(unused)] // currently delegation timestamps are not checked
        time: Leb128EncodedU64,
        subnet: BTreeMap<SubnetId, SubnetView>,
    }

    let certificate: Certificate = parse_certificate(certificate)?;

    if certificate.delegation.is_some() {
        // the specification would allow this, but since the current IC will never do that all certificates
        // with nested delegations are automatically invalid. We abort here to avoid unnecessary computation.
        return Err(CertificateValidationError::MultipleSubnetDelegationsNotAllowed);
    };

    verify_certificate_signature(&certificate, root_pk)?;

    let replica_labeled_tree = parse_tree(certificate.tree)?;
    let subnet_state =
        SubnetCertificateData::deserialize(LabeledTreeDeserializer::new(&replica_labeled_tree))
            .map_err(|err| {
                CertificateValidationError::DeserError(format!(
                    "failed to unpack replica state from a labeled tree: {}",
                    err
                ))
            })?;

    let subnet_info = subnet_state.subnet.get(subnet_id).ok_or_else(|| {
        CertificateValidationError::MalformedHashTree(format!(
            "cannot find subnet information for subnet {} in the tree",
            subnet_id
        ))
    })?;
    let canister_id_ranges: Vec<(CanisterId, CanisterId)> =
        serde_cbor::from_slice(&subnet_info.canister_ranges).map_err(|err| {
            CertificateValidationError::DeserError(format!(
                "failed to unpack canister range: {}",
                err
            ))
        })?;

    if !&canister_id_ranges
        .iter()
        .any(|(range_start, range_end)| (range_start..=range_end).contains(&canister_id))
    {
        return Err(CertificateValidationError::CanisterIdOutOfRange);
    }

    let public_key = parse_threshold_sig_key_from_der(&subnet_info.public_key).map_err(|err| {
        CertificateValidationError::DeserError(format!("failed to deserialize public key: {}", err))
    })?;
    Ok(public_key)
}

fn parse_certificate(certificate: &[u8]) -> Result<Certificate, CertificateValidationError> {
    serde_cbor::from_slice(certificate).map_err(|err| {
        CertificateValidationError::DeserError(format!("failed to decode certificate: {}", err))
    })
}

fn parse_tree(tree: MixedHashTree) -> Result<LabeledTree<Vec<u8>>, CertificateValidationError> {
    LabeledTree::<Vec<u8>>::try_from(tree).map_err(|err| {
        CertificateValidationError::MalformedHashTree(format!(
            "failed to convert hash tree to labeled tree: {:?}",
            err
        ))
    })
}

fn verify_certificate_signature(
    certificate: &Certificate,
    key: &ThresholdSigPublicKey,
) -> Result<(), CertificateValidationError> {
    let digest = CryptoHashOfPartialState::from(CryptoHash(certificate.tree.digest().to_vec()));
    let content = CertificationContent::new(digest.clone());
    let sig = CombinedThresholdSigOf::new(CombinedThresholdSig(certificate.signature.to_vec()));
    verify_combined(&content, &sig, key).map_err(|err| {
        CertificateValidationError::InvalidSignature(format!(
            "certificate_tree_hash={:?}, sig={:?}, pk={:?}, error={:?}",
            digest, certificate.signature, key, err
        ))
    })
}
