use ic_config::embedders::PersistenceType;
use ic_replicated_state::{EmbedderCache, ExecutionState};
use ic_types::CanisterId;
use std::collections::HashMap;

/// The key that uniquely identifies the compiled code.
/// Note that instead of storing the whole wasm source code, we store only the
/// SHA-256 hash assuming that there will be no collisions
#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub(crate) struct Key {
    canister_id: CanisterId,
    persistence_type: PersistenceType,
    wasm_source_hash: [u8; 32],
}

/// Caches compiled code for queries calls.
/// New entries are added here only if the compiled code missing from the
/// corresponding execution state, which happens only after replica restart
/// without any update calls.
pub(crate) struct CompilationCache {
    cache: HashMap<Key, EmbedderCache>,
}

impl CompilationCache {
    pub(crate) fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    // Gets the compiled code for the given execution state.
    pub(crate) fn get(
        &self,
        canister_id: CanisterId,
        state: &ExecutionState,
    ) -> Option<EmbedderCache> {
        let key = Key {
            canister_id,
            persistence_type: state.persistence_type(),
            wasm_source_hash: state.wasm_binary.hash_sha256(),
        };
        self.cache.get(&key).cloned()
    }

    // Saves the compiled code for the given execution state.
    // If the entry already exists, then it returns the existing entry
    // without updating the cache.
    pub(crate) fn insert(
        &mut self,
        canister_id: CanisterId,
        state: &ExecutionState,
        embedder_cache: EmbedderCache,
    ) -> EmbedderCache {
        let key = Key {
            canister_id,
            persistence_type: state.persistence_type(),
            wasm_source_hash: state.wasm_binary.hash_sha256(),
        };
        self.cache
            .insert(key, embedder_cache.clone())
            .unwrap_or(embedder_cache)
    }
}
