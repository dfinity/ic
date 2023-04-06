use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use ic_base_types::CanisterId;
use ic_error_types::UserError;
use ic_replicated_state::ReplicatedState;
use ic_types::{ingress::WasmResult, messages::UserQuery, Cycles, Time, UserId};

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
#[derive(Default)]
pub(crate) struct QueryCache {
    // HashMap is ok, as those are non-replicated queries.
    cache: Arc<RwLock<HashMap<EntryKey, EntryValue>>>,
}

impl QueryCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn valid_result(
        &self,
        key: &EntryKey,
        env: &EntryEnv,
    ) -> Option<Result<WasmResult, UserError>> {
        if let Some(value) = self.cache.read().unwrap().get(key) {
            if value.is_valid(env) {
                return Some(value.result());
            } else {
                // TODO: upgrade the lock and remove the key.
                // self.cache.write().unwrap().remove(key);
            }
        }
        None
    }

    pub(crate) fn insert(&self, key: EntryKey, value: EntryValue) -> Option<EntryValue> {
        self.cache.write().unwrap().insert(key, value)
    }
}
