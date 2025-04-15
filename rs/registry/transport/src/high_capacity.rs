//! For background, see remarks about HighCapacity* types in ./.../transport.proto.
//!
//! At least for now, this module just contains conversion to HighCapacity*
//! types. (The set of implemented conversions probably isn't comprehensive, so
//! feel free to add needed conversions that seem to be missing.) As such, this
//! module can stay private (which is nice).
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
    high_capacity_registry_mutation, HighCapacityRegistryAtomicMutateRequest,
    HighCapacityRegistryMutation, RegistryAtomicMutateRequest, RegistryMutation,
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

#[path = "high_capacity_tests.rs"]
#[cfg(test)]
mod tests;
