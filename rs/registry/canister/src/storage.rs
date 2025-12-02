use crate::{flags::is_chunkifying_large_values_enabled, registry::MAX_REGISTRY_DELTAS_SIZE};
use ic_nervous_system_chunks::Chunks;
use ic_registry_canister_chunkify::chunkify_composite_mutation;
use ic_registry_transport::pb::v1::{
    HighCapacityRegistryAtomicMutateRequest, RegistryAtomicMutateRequest,
};
use ic_stable_structures::{
    DefaultMemoryImpl,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
};
use prost::Message;
use std::cell::RefCell;

const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const CHUNKS_MEMORY_ID: MemoryId = MemoryId::new(1);
const NODE_PROVIDER_RATE_LIMITER_MEMORY_ID: MemoryId = MemoryId::new(2);
const NODE_OPERATOR_RATE_LIMITER_MEMORY_ID: MemoryId = MemoryId::new(3);

/// A RegistryAtomicMutateRequest that has an encoded size greater than this
/// will cause a panic when it is passed to changelog_insert (or maybe_chunkify,
/// which is called by changelog_insert).
///
/// The right to increase this later is reserved. Therefore, nothing should
/// hinge on the current specific value.
///
/// How this value was chosen: The ICP currently has a 2 MiB message size limit.
/// It would not make sense for this to be only a little bit larger than that,
/// because if it were only a little bit larger, we are hardly enhancing our
/// capabilities. At the same time, a higher limit is not needed (yet).
/// Therefore, 5x the message size limit seems appropriate (for now).
pub(crate) const MAX_CHUNKABLE_ATOMIC_MUTATION_LEN: usize = 10 * (1024 * 1024);

/// The value of this is slightly less than MAX_REGISTRY_DELTAS to minimize when
/// chunking is performed.
///
/// The reason this is not exactly equal to MAX_REGISTRY_DELTAS to allow for the
/// addition of a timestamp, and other such incidental issues.
///
/// Notice that the amount by which this is less than MAX_REGISTRY_DELTAS is
/// very small compared to MAX_REGISTRY_DELTAS itself: approx 1_300_000 vs. 100.
const MIN_CHUNKABLE_ATOMIC_MUTATION_LEN: usize = MAX_REGISTRY_DELTAS_SIZE - 100;

type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static UPGRADES_MEMORY: RefCell<VM> = RefCell::new({
        MEMORY_MANAGER.with(|mm| mm.borrow().get(UPGRADES_MEMORY_ID))
    });

    static CHUNKS: RefCell<Chunks<VM>> = RefCell::new({
        MEMORY_MANAGER.with(|mm| Chunks::init(mm.borrow().get(CHUNKS_MEMORY_ID)))
    });
}

pub fn with_upgrades_memory<R>(f: impl FnOnce(&VM) -> R) -> R {
    UPGRADES_MEMORY.with(|um| {
        let upgrades_memory = &um.borrow();
        f(upgrades_memory)
    })
}

pub(crate) fn with_chunks<R>(f: impl FnOnce(&Chunks<VM>) -> R) -> R {
    CHUNKS.with(|chunks| {
        let chunks = chunks.borrow();
        f(&chunks)
    })
}

// Used to create the rate limiter
pub(crate) fn get_node_provider_rate_limiter_memory() -> VM {
    MEMORY_MANAGER.with(|mm| mm.borrow().get(NODE_PROVIDER_RATE_LIMITER_MEMORY_ID))
}

// Used to create the node operator rate limiter
pub fn get_node_operator_rate_limiter_memory() -> VM {
    MEMORY_MANAGER.with(|mm| mm.borrow().get(NODE_OPERATOR_RATE_LIMITER_MEMORY_ID))
}

/// Converts to HighCapacity version of input.
///
/// When the input is "too large" to simply transcribe to the HighCapacity type,
/// "large" blobs are stored into CHUNKS, rather than remaining inline.
///
/// However, even with chunking, the input's size is limited by
/// MAX_CHUNKABLE_ATOMIC_MUTATION_LEN. If this limit is exceeded, this function
/// panics.
pub(crate) fn chunkify_composite_mutation_if_too_large(
    original_mutation: RegistryAtomicMutateRequest,
) -> HighCapacityRegistryAtomicMutateRequest {
    // If chunking is not enabled, simply transcribe.
    if !is_chunkifying_large_values_enabled() {
        return HighCapacityRegistryAtomicMutateRequest::from(original_mutation);
    }

    // Panic if the input is too large.
    if original_mutation.encoded_len() > MAX_CHUNKABLE_ATOMIC_MUTATION_LEN {
        let first_key = original_mutation
            .mutations
            .first()
            .map(|prime_mutation| String::from_utf8_lossy(&prime_mutation.key));
        panic!(
            "Mutation too large. First key = {:?}. Encoded size = {}",
            first_key,
            original_mutation.encoded_len(),
        );
    }

    // If the input is small, simply transcribe it.
    let is_small = original_mutation.encoded_len() < MIN_CHUNKABLE_ATOMIC_MUTATION_LEN;
    if is_small {
        return HighCapacityRegistryAtomicMutateRequest::from(original_mutation);
    }

    // Otherwise, the input is "large", so, chunkify it.
    CHUNKS.with(|chunks| {
        let mut chunks = chunks.borrow_mut();
        let chunks = &mut *chunks;
        chunkify_composite_mutation(original_mutation, chunks)
    })
}

#[cfg(test)]
mod tests;
