use ic_certified_vars::{verify_certificate, CertificateValidationError};
use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
use ic_interfaces::registry::RegistryTransportRecord;
use ic_registry_transport::pb::v1::{
    registry_mutation::Type, CertifiedResponse, RegistryAtomicMutateRequest,
};
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, CanisterId, RegistryVersion, Time};
use prost::Message;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use tree_deserializer::{types::Leb128EncodedU64, LabeledTreeDeserializer};

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
    SubnetDelegationNotAllowed,
}

#[derive(Deserialize)]
struct CertifiedPayload {
    current_version: Leb128EncodedU64,
    #[serde(default)]
    delta: BTreeMap<u64, Protobuf<RegistryAtomicMutateRequest>>,
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
        Cve::SubnetDelegationNotAllowed => Ce::SubnetDelegationNotAllowed,
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
                    "version range not continuous: {} follows {}",
                    next_version, prev_version,
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

/// Parses a response of the "get_certified_changes_since" registry method,
/// validates data integrity and authenticity and returns
///   * The list of changes to apply.
///   * The latest version available (might be greater than the version of the
///     last received delta if there were too many deltas to send in one go).
///   * The time when the received data was last certified by the subnet.
pub fn decode_certified_deltas(
    since_version: u64,
    canister_id: &CanisterId,
    nns_pk: &ThresholdSigPublicKey,
    payload: &[u8],
) -> Result<(Vec<RegistryTransportRecord>, RegistryVersion, Time), CertificationError> {
    let certified_response = CertifiedResponse::decode(payload).map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to decode certified response from {}: {:?}",
            canister_id, err
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
            "failed to deserialize MixedHashTree from {}: {:?}",
            canister_id, err
        ))
    })?;

    // Verify the authenticity of the root hash stored by the canister in the
    // certified_data field, and get the time on the certificate.
    let time = verify_certificate(
        &certified_response.certificate[..],
        canister_id,
        nns_pk,
        mixed_hash_tree.digest().as_bytes(),
    )
    .map_err(embed_certificate_error)?;

    // Extract structured deltas from their tree representation.
    let labeled_tree = LabeledTree::<Vec<u8>>::try_from(mixed_hash_tree).map_err(|err| {
        CertificationError::MalformedHashTree(format!(
            "failed to convert hash tree to labeled tree: {:?}",
            err
        ))
    })?;

    let certified_payload = CertifiedPayload::deserialize(LabeledTreeDeserializer::new(
        &labeled_tree,
    ))
    .map_err(|err| {
        CertificationError::DeserError(format!(
            "failed to unpack certified payload from the labeled tree: {}",
            err
        ))
    })?;

    // Validate that the deltas form a proper range and convert them to the
    // format that RegistryClient wants.
    let current_version = validate_version_range(since_version, &certified_payload)?;

    let changes = certified_payload
        .delta
        .into_iter()
        .flat_map(|(v, mutate_req)| {
            mutate_req.0.mutations.into_iter().map(move |m| {
                let value = if m.mutation_type == Type::Delete as i32 {
                    None
                } else {
                    Some(m.value)
                };
                RegistryTransportRecord {
                    key: String::from_utf8_lossy(&m.key[..]).to_string(),
                    value,
                    version: RegistryVersion::from(v),
                }
            })
        })
        .collect();

    Ok((changes, RegistryVersion::from(current_version), time))
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

        impl<'de, T: prost::Message + Default> serde::de::Visitor<'de> for ProtobufVisitor<T> {
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
