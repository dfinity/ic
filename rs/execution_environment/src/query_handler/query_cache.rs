use ic_base_types::CanisterId;
use ic_error_types::UserError;
use ic_replicated_state::ReplicatedState;
use ic_types::{ingress::WasmResult, messages::UserQuery, CountBytes, Cycles, Time, UserId};
use ic_utils_lru_cache::LruCache;
use std::{mem::size_of_val, sync::Mutex};

/// Query Cache entry key.
///
/// The key is to distinguish query cache entries, i.e. entries with different
/// keys are (almost) completely independent from each other.
#[derive(Eq, Hash, PartialEq)]
pub(crate) struct EntryKey {
    /// Query source.
    pub source: UserId,
    /// Query receiving canister (destination).
    pub receiver: CanisterId,
    /// Receiving canister method name.
    pub method_name: String,
    /// Receiving canister method payload (argument).
    pub method_payload: Vec<u8>,
}

impl CountBytes for EntryKey {
    fn count_bytes(&self) -> usize {
        size_of_val(self) + self.method_name.len() + self.method_payload.len()
    }
}

impl From<&UserQuery> for EntryKey {
    fn from(query: &UserQuery) -> Self {
        Self {
            source: query.source,
            receiver: query.receiver,
            method_name: query.method_name.clone(),
            method_payload: query.method_payload.clone(),
        }
    }
}

/// Query Cache entry environment metadata.
///
/// The structure captures the environment metadata. The cache entry is valid
/// only when its environment metadata matches the current state environment.
pub(crate) struct EntryEnv {
    /// The Consensus-determined time when the cache entry was created.
    pub batch_time: Time,
    /// Receiving canister version.
    pub canister_version: u64,
    /// Receiving canister cycles balance.
    pub canister_balance: Cycles,
}

impl CountBytes for EntryEnv {
    fn count_bytes(&self) -> usize {
        size_of_val(self)
    }
}

impl TryFrom<(&EntryKey, &ReplicatedState)> for EntryEnv {
    type Error = UserError;

    fn try_from((key, state): (&EntryKey, &ReplicatedState)) -> Result<Self, Self::Error> {
        let canister = state.get_active_canister(&key.receiver)?;
        Ok(Self {
            batch_time: state.metadata.batch_time,
            canister_version: canister.system_state.canister_version,
            canister_balance: canister.system_state.balance(),
        })
    }
}

/// Query Cache entry value.
pub(crate) struct EntryValue {
    env: EntryEnv,
    result: Result<WasmResult, UserError>,
}

impl CountBytes for EntryValue {
    fn count_bytes(&self) -> usize {
        self.env.count_bytes() + self.result.count_bytes()
    }
}

impl EntryValue {
    pub(crate) fn new(env: EntryEnv, result: Result<WasmResult, UserError>) -> Self {
        Self { env, result }
    }

    pub(crate) fn is_valid(&self, env: &EntryEnv) -> bool {
        self.env.batch_time == env.batch_time
            && self.env.canister_version == env.canister_version
            && self.env.canister_balance == env.canister_balance
    }

    pub(crate) fn result(&self) -> Result<WasmResult, UserError> {
        self.result.clone()
    }
}

/// Replica Query Cache Implementation.
pub(crate) struct QueryCache {
    // We can't use `RwLock`, as the `LruCache::get()` requires mutable reference
    // to update the LRU.
    cache: Mutex<LruCache<EntryKey, EntryValue>>,
}

impl CountBytes for QueryCache {
    fn count_bytes(&self) -> usize {
        size_of_val(self) + self.cache.lock().unwrap().count_bytes()
    }
}

impl Default for QueryCache {
    fn default() -> Self {
        QueryCache {
            cache: Mutex::new(LruCache::new((u64::MAX / 2).into())),
        }
    }
}

impl QueryCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get_valid_result(
        &self,
        key: &EntryKey,
        env: &EntryEnv,
    ) -> Option<Result<WasmResult, UserError>> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(value) = cache.get(key) {
            if value.is_valid(env) {
                return Some(value.result());
            } else {
                cache.pop(key);
            }
        }
        None
    }

    pub(crate) fn insert(&self, key: EntryKey, value: EntryValue) {
        let size = (key.count_bytes() + value.count_bytes()) as u64;
        self.cache.lock().unwrap().put(key, value, size.into());
    }
}
