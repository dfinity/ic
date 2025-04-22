use ic_nervous_system_chunks::Chunks;
use ic_registry_transport::pb::v1::{
    high_capacity_registry_mutation, high_capacity_registry_value,
    HighCapacityRegistryAtomicMutateRequest, HighCapacityRegistryMutation,
    HighCapacityRegistryValue, LargeValueChunkKeys, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_stable_structures::Memory;

/// Values of length less than this are not put into Chunks.
///
/// How this value was chosen: It is certainly wasteful if this has a value that
/// is < 32, because that is the length of a SHA-256 hash with which we would
/// replace the inlined value itself! Even if this were a bit larger than that,
/// it would be wasteful, because we would be forcing clients to perform a
/// follow up `get_chunk` canister method call to get the original value. At the
/// same time, this should also be "significantly less than the 1.3 MiB Registry
/// changelog limit (see MAX_REGISTRY_DELTAS_SIZE); otherwise, it won't be
/// possible to support atomic ("composite") mutations containing many
/// non-atommic ("prime") mutations. This seems to be a happy medium between
/// 1.3e6 and 32.
const MIN_CHUNKABLE_VALUE_LEN: usize = 10_000;

/// Returns an equivalent value; if the input is "large", data is sloughed off
/// to chunks.
///
/// The definition of "large" is controlled by MIN_CHUNKABLE_VALUE_LEN.
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

/// Gets chunks, concatenates them, and returns the concatenation.
///
/// Panics if one of the chunks is not found (the caller should have good reason
/// to believe that large_value_chunk_keys is actually valid, and not just
/// fishing around).
pub fn dechunkify<M: Memory>(
    large_value_chunk_keys: &LargeValueChunkKeys,
    chunks: &Chunks<M>,
) -> Vec<u8> {
    let LargeValueChunkKeys {
        chunk_content_sha256s,
    } = large_value_chunk_keys;

    // Fetch chunks, and concatenate them.
    let mut result = vec![];
    for key in chunk_content_sha256s {
        result.append(&mut chunks.get_chunk(key).unwrap());
    }

    result
}

/// Decodes value into an R.
///
/// Returns None if value is a deletion. (Otherwise, returns Some.)
///
/// (chunks is needed in case value's content is LargeValueChunkKeys.)
///
/// Possible reason(s) for panic
///
///     1. Failure to decode as R.
pub fn decode_high_capacity_registry_value<R, M>(
    value: &HighCapacityRegistryValue,
    chunks: &Chunks<M>,
) -> Option<R>
where
    R: prost::Message + Default,
    M: Memory,
{
    let Some(content) = &value.content else {
        // DO NOT MERGE - Log? Verify that when the `value` PB field is empty,
        // then the Rust field value.content is set to None.
        return Some(R::default());
    };

    let decoded = match content {
        high_capacity_registry_value::Content::DeletionMarker(deletion_marker) => {
            if *deletion_marker {
                return None;
            }

            // DO NOT MERGE - Log?
            // Why this is the right thing to do: If value is not a deletion,
            // then it must have some value, and it would seem that the value
            // must be empty.
            return Some(R::default());
        }

        high_capacity_registry_value::Content::Value(value) => R::decode(value.as_slice()),

        high_capacity_registry_value::Content::LargeValueChunkKeys(large_value_chunk_keys) => {
            let value = dechunkify(large_value_chunk_keys, chunks);
            R::decode(value.as_slice())
        }
    };

    Some(decoded.unwrap())
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
