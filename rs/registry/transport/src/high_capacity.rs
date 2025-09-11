//! For background, see remarks about HighCapacity* types in ./.../transport.proto.
//!
//! At least for now, this module contains various conversions. Some are "dumb
//! trascriptions", while others (smartly) "dechunkify".
//!
//! By "dumb transcription", we simply mean that when converting TO
//! high-capacity types, there is NO chunking. Furthermore, a "dumb
//! transcription" FROM high-capacity type does NOT dechunkify. Transcribing TO
//! high-capacity types is done by implementing the From trait, but transcribing
//! FROM high-capacity types is done via TryFrom (since there is no way that
//! non-high-capacity types can handle LargeValueChunkKeys).
//!
//! Within the registry canister itself, Chunks is used to dechunkify. Whereas,
//! registry clients can use various dechunkify* functions defined here, and
//! (publicly) re-exported by the root module.

use crate::{
    Error,
    pb::v1::{
        HighCapacityRegistryAtomicMutateRequest, HighCapacityRegistryDelta,
        HighCapacityRegistryMutation, HighCapacityRegistryValue, LargeValueChunkKeys,
        RegistryAtomicMutateRequest, RegistryDelta, RegistryMutation, RegistryValue,
        high_capacity_registry_get_value_response, high_capacity_registry_mutation,
        high_capacity_registry_value, registry_mutation,
    },
};
use async_trait::async_trait;
use ic_crypto_sha2::Sha256;
use mockall::automock;

mod downgrade_get_changes_since_response {
    use super::*;

    impl TryFrom<HighCapacityRegistryDelta> for RegistryDelta {
        type Error = String;

        fn try_from(original: HighCapacityRegistryDelta) -> Result<RegistryDelta, String> {
            let HighCapacityRegistryDelta { key, values } = original;

            let values = values
                .into_iter()
                .map(RegistryValue::try_from)
                .collect::<Result<Vec<RegistryValue>, String>>()?;

            Ok(RegistryDelta { key, values })
        }
    }

    impl TryFrom<HighCapacityRegistryValue> for RegistryValue {
        type Error = String;

        fn try_from(original: HighCapacityRegistryValue) -> Result<RegistryValue, String> {
            let HighCapacityRegistryValue {
                version,
                content,
                timestamp_nanoseconds,
            } = original;

            let (value, deletion_marker) = match content {
                None => (vec![], false),
                Some(high_capacity_registry_value::Content::Value(value)) => (value, false),

                Some(high_capacity_registry_value::Content::DeletionMarker(deletion_marker)) => {
                    (vec![], deletion_marker)
                }

                Some(high_capacity_registry_value::Content::LargeValueChunkKeys(_)) => {
                    return Err("Unable to convert to legacy type, \
                                because of large chunked value."
                        .to_string());
                }
            };

            Ok(RegistryValue {
                version,
                value,
                deletion_marker,
                timestamp_nanoseconds,
            })
        }
    }
} // mod downgrade_get_changes_since_response

impl From<RegistryAtomicMutateRequest> for HighCapacityRegistryAtomicMutateRequest {
    fn from(original: RegistryAtomicMutateRequest) -> HighCapacityRegistryAtomicMutateRequest {
        let RegistryAtomicMutateRequest {
            mutations,
            preconditions,
        } = original;

        let mutations = mutations
            .into_iter()
            .map(HighCapacityRegistryMutation::from)
            .collect::<Vec<_>>();

        let timestamp_nanoseconds = 0;

        HighCapacityRegistryAtomicMutateRequest {
            mutations,
            preconditions,
            timestamp_nanoseconds,
        }
    }
}

impl From<RegistryMutation> for HighCapacityRegistryMutation {
    fn from(original: RegistryMutation) -> HighCapacityRegistryMutation {
        let RegistryMutation {
            mutation_type,
            key,
            value,
        } = original;

        let content = Some(high_capacity_registry_mutation::Content::Value(value));

        HighCapacityRegistryMutation {
            mutation_type,
            key,
            content,
        }
    }
}

impl From<Option<high_capacity_registry_mutation::Content>>
    for high_capacity_registry_value::Content
{
    fn from(original: Option<high_capacity_registry_mutation::Content>) -> Self {
        // Treat None the same as Value(vec![]).
        let Some(original) = original else {
            return high_capacity_registry_value::Content::Value(vec![]);
        };

        match original {
            high_capacity_registry_mutation::Content::Value(value) => {
                high_capacity_registry_value::Content::Value(value)
            }
            high_capacity_registry_mutation::Content::LargeValueChunkKeys(
                large_value_chunk_keys,
            ) => high_capacity_registry_value::Content::LargeValueChunkKeys(large_value_chunk_keys),
        }
    }
}
impl TryFrom<high_capacity_registry_value::Content>
    for high_capacity_registry_get_value_response::Content
{
    type Error = String;

    fn try_from(original: high_capacity_registry_value::Content) -> Result<Self, String> {
        match original {
            high_capacity_registry_value::Content::Value(ok) => Ok(Self::Value(ok)),

            high_capacity_registry_value::Content::DeletionMarker(_) => {
                Err("get_value responses cannot represent deletion_marker.".to_string())
            }

            high_capacity_registry_value::Content::LargeValueChunkKeys(ok) => {
                Ok(Self::LargeValueChunkKeys(ok))
            }
        }
    }
}

impl HighCapacityRegistryValue {
    pub fn is_present(&self) -> bool {
        match &self.content {
            Some(high_capacity_registry_value::Content::DeletionMarker(
                deletion_marker,
            )) => {
                // In general, we would expect deletion_marker to be true. But
                // if it is false, it is always treated the same as
                // Value(vec![]).
                !deletion_marker
            }

            None // This is treated like Value(vec![]).
            | Some(high_capacity_registry_value::Content::Value(_))
            | Some(high_capacity_registry_value::Content::LargeValueChunkKeys(_)) => {
                true
            }
        }
    }
}

/// This is just a "thin wrapper" around Registry's `get_chunk` method.
#[automock]
#[async_trait]
pub trait GetChunk {
    async fn get_chunk_without_validation(&self, content_sha256: &[u8]) -> Result<Vec<u8>, String>;
}

/// Returns a blob.
///
/// If the mutation was a delete, returns None.
///
/// If the content has the blob inline, returns that.
///
/// Otherwise, content uses LargeValueChunkKeys. In this case, fetches the
/// chunks, concatenates them, and returns the resulting monolithic blob.
///
/// Possible reasons for returning Err:
///
///   1. get_chunk call fail.
///   2. content does not have value
pub async fn dechunkify_mutation_value(
    mutation: HighCapacityRegistryMutation,
    get_chunk: &(impl GetChunk + Sync),
) -> Result<Option<Vec<u8>>, Error> {
    let mutation_type =
        registry_mutation::Type::try_from(mutation.mutation_type).map_err(|err| {
            Error::MalformedMessage(format!(
                "Unable to determine mutation's type. Cause: {err}. mutation: {mutation:#?}",
            ))
        })?;

    if mutation_type == registry_mutation::Type::Delete {
        return Ok(None);
    }

    let HighCapacityRegistryMutation {
        content,
        mutation_type: _,
        key: _,
    } = mutation;

    let Some(content) = content else {
        return Ok(Some(vec![]));
    };

    use high_capacity_registry_mutation::Content as C;
    let large_value_chunk_keys = match content {
        C::LargeValueChunkKeys(ok) => ok,

        C::Value(value) => {
            return Ok(Some(value));
        }
    };

    let monolithic_blob = dechunkify(get_chunk, &large_value_chunk_keys)
        .await
        .map_err(Error::UnknownError)?;

    Ok(Some(monolithic_blob))
}

/// Smartly converts from HighCapacityRegistryDelta to (non-high-capacity)
/// RegistryDelta.
///
/// It is often useful to call this right after calling deserialize_get_changes_since_response.
pub async fn dechunkify_delta(
    delta: HighCapacityRegistryDelta,
    get_chunk: &(impl GetChunk + Sync),
) -> Result<RegistryDelta, Error> {
    let HighCapacityRegistryDelta {
        key,
        values: original_values,
    } = delta;

    let mut values = vec![];
    for value in original_values {
        values.push(dechunkify_value(value, get_chunk).await?);
    }

    Ok(RegistryDelta { key, values })
}

pub async fn dechunkify_get_value_response_content(
    content: high_capacity_registry_get_value_response::Content,
    get_chunk: &(impl GetChunk + Sync),
) -> Result<Vec<u8>, Error> {
    match content {
        high_capacity_registry_get_value_response::Content::Value(value) => Ok(value),

        high_capacity_registry_get_value_response::Content::LargeValueChunkKeys(
            large_value_chunk_keys,
        ) => dechunkify(get_chunk, &large_value_chunk_keys)
            .await
            .map_err(|err| {
                Error::UnknownError(format!("Unable to dechunkify get_value response: {err}",))
            }),
    }
}

// Privates

async fn dechunkify_value(
    value: HighCapacityRegistryValue,
    get_chunk: &(impl GetChunk + Sync),
) -> Result<RegistryValue, Error> {
    let HighCapacityRegistryValue {
        version,
        content,
        timestamp_nanoseconds,
    } = value;

    let value = match content {
        Some(content) => dechunkify_value_content(content, get_chunk).await?,
        None => Some(vec![]),
    };
    let (value, deletion_marker) = match value {
        None => (vec![], true),
        Some(value) => (value, false),
    };

    Ok(RegistryValue {
        value,
        version,
        deletion_marker,
        timestamp_nanoseconds,
    })
}

async fn dechunkify_value_content(
    content: high_capacity_registry_value::Content,
    get_chunk: &(impl GetChunk + Sync),
) -> Result<Option<Vec<u8>>, Error> {
    match content {
        high_capacity_registry_value::Content::Value(value) => Ok(Some(value)),

        high_capacity_registry_value::Content::DeletionMarker(deletion_marker) => {
            let result = if deletion_marker { None } else { Some(vec![]) };

            Ok(result)
        }

        high_capacity_registry_value::Content::LargeValueChunkKeys(keys) => {
            let monolithic_blob = dechunkify(get_chunk, &keys).await.map_err(|err| {
                Error::UnknownError(format!("Unable to reconstitute chunked/large value: {err}",))
            })?;

            Ok(Some(monolithic_blob))
        }
    }
}

/// Returns concatenation of chunks.
///
/// Fetches each chunk using get_chunk_with_validation.
async fn dechunkify(
    get_chunk: &(impl GetChunk + Sync),
    keys: &LargeValueChunkKeys,
) -> Result<Vec<u8>, String> {
    let mut result = vec![];
    // Chunks could instead be fetched in parallel.
    for key in &keys.chunk_content_sha256s {
        let mut chunk_content = get_chunk_with_validation(get_chunk, key).await?;
        result.append(&mut chunk_content);
    }
    Ok(result)
}

/// Verification is needed because `get_chunk` is a query.
async fn get_chunk_with_validation(
    get_chunk: &(impl GetChunk + Sync),
    content_sha256: &[u8],
) -> Result<Vec<u8>, String> {
    let chunk_content = get_chunk
        .get_chunk_without_validation(content_sha256)
        .await?;

    // Verify chunk.
    if Sha256::hash(&chunk_content) != content_sha256 {
        let len = chunk_content.len();
        let snippet_len = 20.min(len);
        return Err(format!(
            "Chunk content hash does not match: len={}, head={:?}, tail={:?} SHA256={:?}",
            len,
            &chunk_content[..snippet_len],
            &chunk_content[len - snippet_len..len],
            content_sha256,
        ));
    }

    Ok(chunk_content)
}

#[path = "high_capacity_tests.rs"]
#[cfg(test)]
mod tests;
