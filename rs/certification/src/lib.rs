use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;

use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_crypto_utils_threshold_sig::{verify_combined, verify_combined_with_cache};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_types::{
    consensus::certification::CertificationContent,
    crypto::{
        threshold_sig::ThresholdSigPublicKey, CombinedThresholdSig, CombinedThresholdSigOf,
        CryptoHash,
    },
    messages::{Blob, Certificate},
    CanisterId, CryptoHashOfPartialState, PrincipalId, SubnetId, Time,
};
use serde::Deserialize;
use tree_deserializer::{types::Leb128EncodedU64, LabeledTreeDeserializer};

#[cfg(test)]
mod tests;

/// Describes an error that occurred during parsing and validation of the result
/// of a `RegistryCanister::get_certified_changes_since()` method call.
#[derive(Eq, PartialEq, Debug)]
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
    /// The given subnet id does not match the subnet id in the delegation.
    SubnetIdMismatch {
        provided_subnet_id: SubnetId,
        delegation_subnet_id: SubnetId,
    },
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
            Self::SubnetIdMismatch { provided_subnet_id, delegation_subnet_id } => write!(
                f,
                "provided subnet id {} does not match subnet id in delegation {}",
                provided_subnet_id, delegation_subnet_id,
            ),
        }
    }
}

/// Verifies a certificate and its certified data.
///
/// Verification ensures that
/// * the certificate is well-formed and contains a tree, a signature, and
///   optionally a delegation with a certificate and a subnet ID,
/// * if a delegation is present, that the delegation certificate is valid for
///   the delegation subnet for the canister with ID `canister_id` w.r.t. the
///   `root_pk` (see below for details on verifying a delegation certificate).
/// * the signature is valid, either w.r.t. `root_pk` or w.r.t
///   the delegation key if a delegation is present,
/// * the tree is well-formed and contains time as well as canister information
///   (i.e., certified data) for the canister with ID `canister_id`, and
/// * the canister's certified data is equal to `certified_data`.
///
/// Verification of the delegation certificate ensures that
/// * the certificate is well-formed and contains a tree, a signature, and
///   _no_ further delegation, i.e., it comes directly from the root subnet,
/// * the signature is valid w.r.t. `root_pk`,
/// * the tree is well-formed and contains time as well as subnet information
///   (i.e., a public_key and canister ranges) for the given subnet,
/// * the canister ranges are well-formed and contain the `canister_id`, and
/// * the public key is well-formed.
///
/// Returns the certificate's timestamp, if verification is successful.
pub fn verify_certified_data(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
    certified_data: &[u8],
) -> Result<Time, CertificateValidationError> {
    verify_certified_data_internal(certificate, canister_id, root_pk, certified_data, false)
}

/// Does the same as [`verify_certified_data`] but keeps some verified signatures in cache
/// for efficiency.
pub fn verify_certified_data_with_cache(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
    certified_data: &[u8],
) -> Result<Time, CertificateValidationError> {
    verify_certified_data_internal(certificate, canister_id, root_pk, certified_data, true)
}

/// Verifies a certificate and its certified data with optional signature cache.
/// Internal implementation used by `pub` functions.
/// More details are given in [`verify_certified_data`].
fn verify_certified_data_internal(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
    certified_data: &[u8],
    use_signature_cache: bool,
) -> Result<Time, CertificateValidationError> {
    #[derive(Debug, Deserialize)]
    struct CanisterView {
        certified_data: Blob,
    }

    #[derive(Debug, Deserialize)]
    struct ReplicaState {
        time: Leb128EncodedU64,
        canister: BTreeMap<CanisterId, CanisterView>,
    }

    let verified_certificate =
        verify_certificate_internal(certificate, canister_id, root_pk, use_signature_cache)?;

    let replica_labeled_tree = parse_tree(verified_certificate.tree)?;
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

/// Verifies a certificate.
///
/// Verification ensures that
/// * the certificate is well-formed and contains a tree, a signature, and
///   optionally a delegation with a certificate and a subnet ID,
/// * if a delegation is present, that the delegation certificate is valid for
///   the delegation subnet for the canister with ID `canister_id` w.r.t. the
///   `root_pk` (see below for details on verifying a delegation certificate).
/// * the signature is valid, either w.r.t. `root_pk` or w.r.t
///   the delegation key if a delegation is present,
///
/// Verification of the delegation certificate ensures that
/// * the certificate is well-formed and contains a tree, a signature, and
///   _no_ further delegation, i.e., it comes directly from the root subnet,
/// * the signature is valid w.r.t. `root_pk`,
/// * the tree is well-formed and contains time as well as subnet information
///   (i.e., a public_key and canister ranges) for the given subnet,
/// * the canister ranges are well-formed and contain the `canister_id`, and
/// * the public key is well-formed.
///
/// Returns the verified certificate, if verification is successful.
pub fn verify_certificate(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
) -> Result<Certificate, CertificateValidationError> {
    verify_certificate_internal(certificate, canister_id, root_pk, false)
}

/// Does the same as [`verify_certificate`] but keeps some verified signatures in cache
/// for efficiency.
pub fn verify_certificate_with_cache(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
) -> Result<Certificate, CertificateValidationError> {
    verify_certificate_internal(certificate, canister_id, root_pk, true)
}

/// Verifies a certificate for a read state on the subnet endpoint (i.e. a
/// certificate returned by /api/v2/subnet/<subnet_id>/read_state).
///
/// See doc comments of `verify_certificate` for more details.
///
/// In case a delegation is present, then the delegation certificate is valid
/// for the subnet id that is provided, i.e. the provided subnet id must
/// match the delegation subnet id.
///
/// Additionally the delegation certificate is valid without doing any check
/// on the canister ranges included in the certificate.
pub fn verify_certificate_for_subnet_read_state(
    certificate: &[u8],
    subnet_id: &SubnetId,
    root_pk: &ThresholdSigPublicKey,
) -> Result<Certificate, CertificateValidationError> {
    let certificate: Certificate = parse_certificate(certificate)?;
    let key = if let Some(delegation) = &certificate.delegation {
        let delegation_subnet_id = PrincipalId::try_from(&*delegation.subnet_id)
            .map(SubnetId::from)
            .map_err(|err| {
                CertificateValidationError::DeserError(format!(
                    "failed to parse delegation subnet id: {}",
                    err
                ))
            })?;
        if subnet_id != &delegation_subnet_id {
            return Err(CertificateValidationError::SubnetIdMismatch {
                provided_subnet_id: *subnet_id,
                delegation_subnet_id,
            });
        }

        verify_delegation_certificate(&delegation.certificate, subnet_id, root_pk, None, false)?
    } else {
        *root_pk
    };

    verify_certificate_signature(&certificate, &key, false)?;
    Ok(certificate)
}

/// Verifies a certificate with optional signature cache.
/// Internal implementation used by `pub` functions.
/// More details are given in [`verify_certificate`].
fn verify_certificate_internal(
    certificate: &[u8],
    canister_id: &CanisterId,
    root_pk: &ThresholdSigPublicKey,
    use_signature_cache: bool,
) -> Result<Certificate, CertificateValidationError> {
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
        verify_delegation_certificate(
            &delegation.certificate,
            &subnet_id,
            root_pk,
            Some(canister_id),
            use_signature_cache,
        )?
    } else {
        *root_pk
    };

    verify_certificate_signature(&certificate, &key, use_signature_cache)?;
    Ok(certificate)
}

/// Verifies a delegation certificate.
///
/// See the documentation of `verify_certificate` for more details.
fn verify_delegation_certificate(
    certificate: &[u8],
    subnet_id: &SubnetId,
    root_pk: &ThresholdSigPublicKey,
    canister_id: Option<&CanisterId>,
    use_signature_cache: bool,
) -> Result<ThresholdSigPublicKey, CertificateValidationError> {
    #[derive(Debug, Deserialize)]
    struct SubnetView {
        canister_ranges: Blob,
        public_key: Blob,
    }

    #[derive(Debug, Deserialize)]
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

    verify_certificate_signature(&certificate, root_pk, use_signature_cache)?;

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

    if let Some(canister_id) = canister_id {
        if !&canister_id_ranges
            .iter()
            .any(|(range_start, range_end)| (range_start..=range_end).contains(&canister_id))
        {
            return Err(CertificateValidationError::CanisterIdOutOfRange);
        }
    }

    let public_key = parse_threshold_sig_key_from_der(&subnet_info.public_key).map_err(|err| {
        CertificateValidationError::DeserError(format!("failed to deserialize public key: {}", err))
    })?;
    Ok(public_key)
}

/// Validates a subnet delegation certificate.
///
/// Returns `Ok(())` iff the verification of a delegation certificate
/// as described in the documentation of `verify_certificate` is successful
/// for subnet with ID `subnet_id`, with the exception that no canister ID
/// range check is performed.
pub fn validate_subnet_delegation_certificate(
    certificate: &[u8],
    subnet_id: &SubnetId,
    root_pk: &ThresholdSigPublicKey,
) -> Result<(), CertificateValidationError> {
    verify_delegation_certificate(certificate, subnet_id, root_pk, None, false)
        .map(|_public_key| ())
}

/// Does the same as [`validate_subnet_delegation_certificate`] but keeps some
/// verified signatures in cache for efficiency.
pub fn validate_subnet_delegation_certificate_with_cache(
    certificate: &[u8],
    subnet_id: &SubnetId,
    root_pk: &ThresholdSigPublicKey,
) -> Result<(), CertificateValidationError> {
    verify_delegation_certificate(certificate, subnet_id, root_pk, None, true).map(|_public_key| ())
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
    use_signature_cache: bool,
) -> Result<(), CertificateValidationError> {
    let digest = CryptoHashOfPartialState::from(CryptoHash(certificate.tree.digest().to_vec()));
    let content = CertificationContent::new(digest.clone());
    let sig = CombinedThresholdSigOf::new(CombinedThresholdSig(certificate.signature.to_vec()));
    let threshold_sig_verification_fn = if use_signature_cache {
        verify_combined_with_cache
    } else {
        verify_combined
    };
    threshold_sig_verification_fn(&content, &sig, key).map_err(|err| {
        CertificateValidationError::InvalidSignature(format!(
            "certificate_tree_hash={:?}, sig={:?}, pk={:?}, error={:?}",
            digest, certificate.signature, key, err
        ))
    })
}
