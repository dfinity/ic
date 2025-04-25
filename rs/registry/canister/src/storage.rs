use crate::{flags::is_chunkifying_large_values_enabled, registry::MAX_REGISTRY_DELTAS_SIZE};
use ic_nervous_system_chunks::Chunks;
use ic_registry_canister_chunkify::chunkify_composite_mutation;
use ic_registry_transport::pb::v1::{
    HighCapacityRegistryAtomicMutateRequest, RegistryAtomicMutateRequest,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::DefaultMemoryImpl;
use prost::Message;
use std::cell::RefCell;

const UPGRADES_MEMORY_ID: MemoryId = MemoryId::new(0);
const CHUNKS_MEMORY_ID: MemoryId = MemoryId::new(1);

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
const MAX_CHUNKABLE_ATOMIC_MUTATION_LEN: usize = 10 * (1024 * 1024);

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

/// Converts to HighCapacity version of input.
///
/// When the input is "too large", "large" blobs are stored into CHUNKS, rather
/// than remaining inline.
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
    const SIZE_OF_VERSION: usize = std::mem::size_of::<crate::registry::EncodedVersion>();
    let is_small = original_mutation.encoded_len() + SIZE_OF_VERSION < MAX_REGISTRY_DELTAS_SIZE;
    if is_small {
        return HighCapacityRegistryAtomicMutateRequest::from(original_mutation);
    }

    // Otherwise, if the input is "large", chunkify it.
    CHUNKS.with(|chunks| {
        let mut chunks = chunks.borrow_mut();
        let chunks = &mut *chunks;
        chunkify_composite_mutation(original_mutation, chunks)
    })
}

#[cfg(test)]
mod tests;
