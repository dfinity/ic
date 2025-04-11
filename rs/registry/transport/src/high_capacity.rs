//! For background, see remarks about HighCapacity* types in ./.../transport.proto.
//!
//! At least for now, this module just contains conversion to and from
//! HighCapacity* types. (The set of implemented conversions probably isn't
//! comprehensive, so feel free to add needed conversions that seem to be
//! missing.) As such, this module can stay private (which is nice).
//!
//! Note that when converting to HighCapacity types, there is no chunking; the
//! conversion is just a "transcription".
//!
//! Note that when converting TO HighCapacity the From trait is used, but when
//! converting FROM HighCapacity, TryFrom is used. This asymetry is for the
//! usual reason(s): every non-HighCapacity object has an equivalent
//! HighCapacity version, but not necessarily the other way around. In
//! particular, converting FROM HighCapacity does not really work if the
//! original object uses LargeValueChunkKeys.
//!
//! With the help of Chunks, it is possible to convert "back" from HighCapacity,
//! but that is outside the scope of this crate. Instead, look for such
//! functionality in rs/registry/canister/chunkify (if the functionality you
//! want is not already there, feel free to add it).

use crate::pb::v1::{
    high_capacity_registry_mutation, HighCapacityRegistryAtomicMutateRequest,
    HighCapacityRegistryMutation, RegistryAtomicMutateRequest, RegistryMutation,
    RegistryValue, HighCapacityRegistryValue, high_capacity_registry_value, registry_mutation,
};

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

/// The main reason this would fail is if the original
/// HighCapacityRegistryMutation were invalid. For example, if it had
/// mutation_type=Delete, yet also content=Some(...). Or if the mutation_type
/// i32 cannot be converted to registry_mutation::Type (enum).
impl TryFrom<(/* mutation_type */ i32, Option<high_capacity_registry_mutation::Content>)>
    for high_capacity_registry_value::Content
{
    type Error = String;

    fn try_from(original: (i32, Option<high_capacity_registry_mutation::Content>)) -> Result<Self, String> {
        let (mutation_type, original_content) = original;

        let mutation_type = registry_mutation::Type::try_from(mutation_type)
            .map_err(|err| format!(
                "Unable to convert mutation type ({}) from integer to enum: {}",
                mutation_type, err,
            ))?;

        match mutation_type {
            registry_mutation::Type::Delete => {
                return match original_content {
                    None => {
                        Ok(Self::DeletionMarker(true))
                    }

                    Some(original_content) => {
                        Err(format!(
                            "deleltion_marker true in a mutation, yet has content: {:?} ",
                            original_content,
                        ))
                    }
                };
            }

            registry_mutation::Type::Insert |
            registry_mutation::Type::Update |
            registry_mutation::Type::Upsert => (),
        }


        let original_content = original_content.unwrap_or_else(|| {
            // DO NOT MERGE - Log?
            high_capacity_registry_mutation::Content::Value(vec![])
        });

        let new_content = match original_content {
            high_capacity_registry_mutation::Content::Value(value) => {
                Self::Value(value)
            }

            high_capacity_registry_mutation::Content::LargeValueChunkKeys(large_value_chunk_keys) => {
                Self::LargeValueChunkKeys(large_value_chunk_keys)
            }
        };

        Ok(new_content)
    }
}

/* impl TryFrom<HighCapacityRegistryDelta> for RegistryDelta { // DO NOT MERGE - Delete.
    type Error = String;

    fn try_from(original: HighCapacityRegistryDelta) -> Result<RegistryDelta, String> {
        let HighCapacityRegistryDelta {
            key,
            values,
        } = original;

        let values = values
            .into_iter()
            .map(RegistryValue::try_from)
            .collect::< Result<Vec<_>, String> >()?;

        Ok(RegistryDelta {
            key,
            values,
        })
    }
}
*/

type ValueAndDeletionMarker = (Vec<u8>, bool);

impl TryFrom<HighCapacityRegistryValue> for RegistryValue {
    type Error = String;

    fn try_from(original: HighCapacityRegistryValue) -> Result<RegistryValue, String> {
        let HighCapacityRegistryValue {
            version,
            content,

            timestamp_seconds: _,
        } = original;

        let (value, deletion_marker) = match content {
            Some(content) => ValueAndDeletionMarker::try_from(content)?,

            None => {
                // DO NOT MERGE - Log?
                (vec![], false)
            }
        };

        Ok(RegistryValue {
            version,
            value,
            deletion_marker,
        })
    }
}

impl TryFrom<high_capacity_registry_value::Content> for (Vec<u8>, bool) {
    type Error = String;

    fn try_from(original: high_capacity_registry_value::Content) -> Result<ValueAndDeletionMarker, String> {
        match original {
            high_capacity_registry_value::Content::Value(value) => Ok((value, false)),

            high_capacity_registry_value::Content::DeletionMarker(deletion_marker) =>
                Ok((vec![], deletion_marker)),

            high_capacity_registry_value::Content::LargeValueChunkKeys(_) =>
                Err("Unable to convert from HighCapacity to regular \
                     RegistryValue due to LargeValueChunkKeys".to_string()),
        }
    }
}

#[path = "high_capacity_tests.rs"]
#[cfg(test)]
mod tests;
