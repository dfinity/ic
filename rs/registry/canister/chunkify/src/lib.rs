use ic_nervous_system_chunks::Chunks;
use ic_registry_transport::pb::v1::{
    high_capacity_registry_mutation, HighCapacityRegistryAtomicMutateRequest,
    HighCapacityRegistryMutation, LargeValueChunkKeys, RegistryAtomicMutateRequest,
    RegistryMutation,
};
use ic_stable_structures::Memory;

/// Values of length less than this are not put into Chunks.
///
/// How this value was chosen: It is certainly wasteful if this has a value that
/// is < 32, because that is the length of a SHA-256 hash with which we would
/// replace the inlined value itself! Even if this were a bit larger than that,
/// it would be wasteful, because we would be forcing clients to perform a
/// follow up `get_chunk` canister method call to get the original value. 25x or
/// so seems like a pretty reasonable threshold.
const MIN_CHUNKABLE_VALUE_LEN: usize = 800;

pub fn chunkify_composite_mutation<M: Memory>(
    original_mutation: RegistryAtomicMutateRequest,
    chunks: &mut Chunks<M>,
) -> HighCapacityRegistryAtomicMutateRequest {
    let RegistryAtomicMutateRequest {
        mutations,
        preconditions,
    } = original_mutation;

    let mutations = mutations
        .into_iter()
        .map(|mutation| chunkify_prime_mutation(mutation, chunks))
        .collect::<Vec<_>>();

    let timestamp_seconds = 0;

    HighCapacityRegistryAtomicMutateRequest {
        mutations,
        preconditions,
        timestamp_seconds,
    }
}

fn chunkify_prime_mutation<M: Memory>(
    original_mutation: RegistryMutation,
    chunks: &mut Chunks<M>,
) -> HighCapacityRegistryMutation {
    let RegistryMutation {
        mutation_type,
        key,
        value,
    } = original_mutation;

    let content = if value.len() < MIN_CHUNKABLE_VALUE_LEN {
        high_capacity_registry_mutation::Content::Value(value)
    } else {
        let chunk_content_sha256s = chunks.upsert_monolithic_blob(value);
        high_capacity_registry_mutation::Content::LargeValueChunkKeys(LargeValueChunkKeys {
            chunk_content_sha256s,
        })
    };
    let content = Some(content);

    HighCapacityRegistryMutation {
        mutation_type,
        key,
        content,
    }
}

#[cfg(test)]
mod tests;
