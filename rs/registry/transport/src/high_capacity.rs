//! For background, see remarks about HighCapacity* types in ./.../transport.proto.
//!
//! At least for now, this module just contains conversion to HighCapacity*
//! types. (The set of implemented conversions probably isn't comprehensive, so
//! feel free to add needed conversions that seem to be missing.) As such, this
//! module can stay private (which is nice).
//!
//! Note that when converting to HighCapacity types, there is no chunking; the
//! conversion is just a "transcription".
//!
//! Note that when converting TO HighCapacity the From trait is used, but when
//! converting FROM HighCapacity, TryFrom should be used. This asymetry is for
//! the usual reason(s): every non-HighCapacity object has an equivalent
//! HighCapacity version, but not necessarily the other way around. In
//! particular, converting FROM HighCapacity does not really work if the
//! original object uses LargeValueChunkKeys.
//!
//! With the help of Chunks, it is possible to convert "back" from HighCapacity,
//! but that is outside the scope of this crate. Instead, look for such
//! functionality in rs/registry/canister/chunkify (if the functionality you
//! want is not already there, feel free to add it).

use crate::pb::v1::{
    high_capacity_registry_get_value_response, high_capacity_registry_mutation,
    high_capacity_registry_value, HighCapacityRegistryAtomicMutateRequest,
    HighCapacityRegistryDelta, HighCapacityRegistryGetChangesSinceResponse,
    HighCapacityRegistryMutation, HighCapacityRegistryValue, RegistryAtomicMutateRequest,
    RegistryDelta, RegistryGetChangesSinceResponse, RegistryMutation, RegistryValue,
};

mod downgrade_get_changes_since_response {
    use super::*;

    impl TryFrom<HighCapacityRegistryGetChangesSinceResponse> for RegistryGetChangesSinceResponse {
        type Error = String;

        fn try_from(
            original: HighCapacityRegistryGetChangesSinceResponse,
        ) -> Result<RegistryGetChangesSinceResponse, String> {
            let HighCapacityRegistryGetChangesSinceResponse {
                error,
                version,
                deltas,
            } = original;

            let deltas = deltas
                .into_iter()
                .map(RegistryDelta::try_from)
                .collect::<Result<Vec<RegistryDelta>, String>>()?;

            Ok(RegistryGetChangesSinceResponse {
                error,
                version,
                deltas,
            })
        }
    }

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

                // This gets dropped.
                timestamp_seconds: _,
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

        let timestamp_seconds = 0;

        HighCapacityRegistryAtomicMutateRequest {
            mutations,
            preconditions,
            timestamp_seconds,
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

#[path = "high_capacity_tests.rs"]
#[cfg(test)]
mod tests;
