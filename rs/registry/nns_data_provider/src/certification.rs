use ic_certification::{CertificateValidationError, verify_certified_data};
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces_registry::RegistryRecord;
use ic_registry_transport::{
    GetChunk, dechunkify_mutation_value,
    pb::v1::{CertifiedResponse, HighCapacityRegistryAtomicMutateRequest},
};
use ic_types::{
    CanisterId, RegistryVersion, SubnetId, Time, crypto::threshold_sig::ThresholdSigPublicKey,
};
use prost::Message;
use serde::Deserialize;
use std::{collections::BTreeMap, convert::TryFrom, fmt::Debug};
use tree_deserializer::{LabeledTreeDeserializer, types::Leb128EncodedU64};

#[cfg(test)]
mod tests;

/// Describes an error occurred during parsing and validation of the result of a
/// "get_certified_changes_since" method call.
#[derive(Debug)]
pub enum CertificationError {
    /// Failed to deserialize some part of the response.
    DeserError(String),
    /// The signature verification failed.
    InvalidSignature(String),
    /// The value at path "/canister/<cid>/certified_data" doesn't match the
    /// hash computed from the mixed hash tree with registry deltas.
    CertifiedDataMismatch {
        certified: Vec<u8>,
        computed: Vec<u8>,
    },
    /// Parsing and signature verification was successful, but the list of
    /// deltas doesn't satisfy postconditions of the method.
    InvalidDeltas(String),
    /// The hash tree in the response was not well-formed.
    MalformedHashTree(String),
    /// There are multiple delegation levels in the certification which is (currently) not allowed.
    MultipleSubnetDelegationsNotAllowed,
    /// The canister id is not contained in the canister ranges the subnet is allowed to issue certifications for.
    CanisterIdOutOfRange,
    /// The provided subnet id does not match the subnet id included in the delegation.
    SubnetIdMismatch {
        provided_subnet_id: SubnetId,
        delegation_subnet_id: SubnetId,
    },
    DechunkifyingFailed(ic_registry_transport::Error),
}

#[derive(Deserialize)]
struct CertifiedPayload {
    current_version: Leb128EncodedU64,
    #[serde(default)]
    delta: BTreeMap<u64, Protobuf<HighCapacityRegistryAtomicMutateRequest>>,
}

fn embed_certificate_error(err: CertificateValidationError) -> CertificationError {
    type Cve = CertificateValidationError;
    type Ce = CertificationError;
    match err {
        Cve::DeserError(err) => Ce::DeserError(err),
        Cve::InvalidSignature(err) => Ce::InvalidSignature(err),
        Cve::CertifiedDataMismatch {
            certified,
            computed,
        } => Ce::CertifiedDataMismatch {
            certified,
            computed,
        },
        Cve::MalformedHashTree(err) => Ce::MalformedHashTree(err),
        Cve::MultipleSubnetDelegationsNotAllowed => Ce::MultipleSubnetDelegationsNotAllowed,
        Cve::CanisterIdOutOfRange => Ce::CanisterIdOutOfRange,
        Cve::SubnetIdMismatch {
            provided_subnet_id,
            delegation_subnet_id,
        } => Ce::SubnetIdMismatch {
            provided_subnet_id,
            delegation_subnet_id,
        },
    }
}

/// Validates that changes in the payload form a valid range.  We want to check
/// the following properties:
///
///   1. The version of the first delta is the successor of `since_version`.
///
///   2. Versions of deltas form a continuous range.
///
///   3. If current_version > since_version, the range contains at least one
///      delta.  Note that It is fine for the registry canister to not return
///      all entries up until the current version.  This can happen, e.g., if
///      the list of updates is too long for a single request.
fn validate_version_range(
    since_version: u64,
    p: &CertifiedPayload,
) -> Result<u64, CertificationError> {
    let last_version = p
        .delta
        .keys()
        .try_fold(since_version, |prev_version, next_version| {
            if *next_version != prev_version + 1 {
                Err(CertificationError::InvalidDeltas(format!(
                    "version range not continuous: {next_version} follows {prev_version}",
                )))
            } else {
                Ok(*next_version)
            }
        })?;

    if last_version == since_version && p.current_version.0 > since_version {
        return Err(CertificationError::InvalidDeltas(format!(
            "current version {} is newer than requested {}, but the payload has no deltas",
            p.current_version.0, since_version
        )));
    }

    Ok(p.current_version.0)
}

/// Decodes registry deltas from their hash tree representation.
pub async fn decode_hash_tree(
    since_version: u64,
    hash_tree: MixedHashTree,
    get_chunk: &(impl GetChunk + Sync),
) -> Result<(Vec<RegistryRecord>, RegistryVersion), CertificationError> {
    // Extract structured deltas from their tree representation.
    let labeled_tree = LabeledTree::<Vec<u8>>::try_from(hash_tree).map_err(|err| {
        CertificationError::MalformedHashTree(format!(
            "failed to convert hash tree to labeled tree: {err:?}"
        ))
    })?;

    let certified_payload = CertifiedPayload::deserialize(LabeledTreeDeserializer::new(
        &labeled_tree,
    ))
    .map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to unpack certified payload from the labeled tree: {err}"
        ))
    })?;

    // Validate that the deltas form a proper range and convert them to the
    // format that RegistryClient wants.
    let current_version = validate_version_range(since_version, &certified_payload)?;

    let mut changes = vec![];
    for (version, atomic_mutation) in certified_payload.delta {
        let version = RegistryVersion::from(version);

        for mutation in atomic_mutation.0.mutations {
            let key = String::from_utf8_lossy(&mutation.key[..]).to_string();
            let value: Option<Vec<u8>> = dechunkify_mutation_value(mutation, get_chunk)
                .await
                .map_err(CertificationError::DechunkifyingFailed)?;

            changes.push(RegistryRecord {
                key,
                value,
                version,
            });
        }
    }

    Ok((changes, RegistryVersion::from(current_version)))
}

/// Parses a response of the "get_certified_changes_since" registry method,
/// validates data integrity and authenticity and returns
///   * The list of changes to apply.
///   * The latest version available (might be greater than the version of the
///     last received delta if there were too many deltas to send in one go).
///   * The time when the received data was last certified by the subnet.
pub(crate) async fn decode_certified_deltas(
    since_version: u64,
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    payload: &[u8],
    get_chunk: &(impl GetChunk + Sync),
) -> Result<(Vec<RegistryRecord>, RegistryVersion, Time), CertificationError> {
    let certified_response = CertifiedResponse::decode(payload).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to decode certified response from {canister_id}: {err:?}"
        ))
    })?;

    // Extract the hash trees from the canister response.
    let hash_tree = certified_response.hash_tree.ok_or_else(|| {
        CertificationError::MalformedHashTree(
            "certified response has an empty hash tree".to_string(),
        )
    })?;
    let mixed_hash_tree = MixedHashTree::try_from(hash_tree).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to deserialize MixedHashTree from {canister_id}: {err:?}"
        ))
    })?;

    // Verify the authenticity of the root hash stored by the canister in the
    // certified_data field, and get the time on the certificate.
    let time = verify_certified_data(
        &certified_response.certificate[..],
        canister_id,
        nns_pk,
        mixed_hash_tree.digest().as_bytes(),
    )
    .map_err(embed_certificate_error)?;

    let (changes, current_version) =
        decode_hash_tree(since_version, mixed_hash_tree, get_chunk).await?;

    Ok((changes, current_version, time))
}

/// An auxiliary type that instructs serde to deserialize blob as a protobuf
/// message.
struct Protobuf<T>(T);

impl<'de, T> serde::Deserialize<'de> for Protobuf<T>
where
    T: prost::Message + Default,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use std::fmt;
        use std::marker::PhantomData;

        struct ProtobufVisitor<T: prost::Message>(PhantomData<T>);

        impl<T: prost::Message + Default> serde::de::Visitor<'_> for ProtobufVisitor<T> {
            type Value = Protobuf<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "Protobuf message of type {}",
                    std::any::type_name::<T>()
                )
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                T::decode(v).map(Protobuf).map_err(E::custom)
            }
        }

        let visitor: ProtobufVisitor<T> = ProtobufVisitor(PhantomData);
        deserializer.deserialize_bytes(visitor)
    }
}
