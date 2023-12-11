use ic_base_types::{CanisterId, NumBytes};
use ic_error_types::UserError;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{ingress::WasmResult, messages::UserQuery, CountBytes, Cycles, Time, UserId};
use ic_utils_lru_cache::LruCache;
use prometheus::{Histogram, IntCounter, IntGauge};
use std::{mem::size_of_val, sync::Mutex};

use crate::metrics::duration_histogram;

#[cfg(test)]
mod tests;

////////////////////////////////////////////////////////////////////////
/// Query Cache metrics.
pub(crate) struct QueryCacheMetrics {
    pub hits: IntCounter,
    pub misses: IntCounter,
    pub evicted_entries: IntCounter,
    pub evicted_entries_duration: Histogram,
    pub invalidated_entries: IntCounter,
    pub invalidated_entries_by_time: IntCounter,
    pub invalidated_entries_by_canister_version: IntCounter,
    pub invalidated_entries_by_canister_balance: IntCounter,
    pub invalidated_entries_duration: Histogram,
    pub count_bytes: IntGauge,
    pub len: IntGauge,
}

impl QueryCacheMetrics {
    fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            hits: metrics_registry.int_counter(
                "execution_query_cache_hits_total",
                "The total number of replica side query cache hits",
            ),
            misses: metrics_registry.int_counter(
                "execution_query_cache_misses_total",
                "The total number of replica side query cache misses",
            ),
            evicted_entries: metrics_registry.int_counter(
                "execution_query_cache_evicted_entries_total",
                "The total number of evicted entries in the replica side query cache",
            ),
            evicted_entries_duration: duration_histogram(
                "execution_query_cache_evicted_entries_duration_seconds",
                "The duration of evicted cache entries in seconds",
                metrics_registry,
            ),
            invalidated_entries: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_total",
                "The total number of invalidated entries in the replica side query cache",
            ),
            invalidated_entries_by_time: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_time_total",
                "The total number of invalidated entries due to the changed time",
            ),
            invalidated_entries_by_canister_version: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_canister_version_total",
                "The total number of invalidated entries due to the changed canister version",
            ),
            invalidated_entries_by_canister_balance: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_canister_balance_total",
                "The total number of invalidated entries due to the changed canister balance",
            ),
            invalidated_entries_duration: duration_histogram(
                "execution_query_cache_invalidated_entries_duration_seconds",
                "The duration of invalidated cache entries in seconds",
                metrics_registry,
            ),
            count_bytes: metrics_registry.int_gauge(
                "execution_query_cache_count_bytes",
                "The current replica side query cache size in bytes",
            ),
            len: metrics_registry.int_gauge(
                "execution_query_cache_len",
                "The current replica side query cache len in elements",
            ),
        }
    }
}

////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////
/// Query Cache entry environment metadata.
///
/// The structure captures the environment metadata. The cache entry is valid
/// only when its environment metadata matches the current state environment.
#[derive(PartialEq)]
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

////////////////////////////////////////////////////////////////////////
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

    fn is_valid(&self, env: &EntryEnv) -> bool {
        self.env == *env
    }

    fn is_valid_time(&self, env: &EntryEnv) -> bool {
        self.env.batch_time == env.batch_time
    }

    fn is_valid_canister_version(&self, env: &EntryEnv) -> bool {
        self.env.canister_version == env.canister_version
    }

    fn is_valid_canister_balance(&self, env: &EntryEnv) -> bool {
        self.env.canister_balance == env.canister_balance
    }

    fn result(&self) -> Result<WasmResult, UserError> {
        self.result.clone()
    }

    fn elapsed_seconds(&self, now: Time) -> f64 {
        now.saturating_sub(self.env.batch_time).as_secs_f64()
    }
}

////////////////////////////////////////////////////////////////////////
/// Replica Side Query Cache.
pub(crate) struct QueryCache {
    // We can't use `RwLock`, as the `LruCache::get()` requires mutable reference
    // to update the LRU.
    cache: Mutex<LruCache<EntryKey, EntryValue>>,
    // Query cache metrics (public for tests)
    pub(crate) metrics: QueryCacheMetrics,
}

impl CountBytes for QueryCache {
    fn count_bytes(&self) -> usize {
        size_of_val(self) + self.cache.lock().unwrap().count_bytes()
    }
}

impl QueryCache {
    pub(crate) fn new(metrics_registry: &MetricsRegistry, capacity: NumBytes) -> Self {
        QueryCache {
            cache: Mutex::new(LruCache::new(capacity)),
            metrics: QueryCacheMetrics::new(metrics_registry),
        }
    }

    pub(crate) fn get_valid_result(
        &self,
        key: &EntryKey,
        env: &EntryEnv,
    ) -> Option<Result<WasmResult, UserError>> {
        let mut cache = self.cache.lock().unwrap();
        let now = env.batch_time;

        if let Some(value) = cache.get(key) {
            if value.is_valid(env) {
                let res = value.result();
                // Update the metrics.
                self.metrics.hits.inc();
                let count_bytes = cache.count_bytes() as i64;
                self.metrics.count_bytes.set(count_bytes);
                // The cache entry is valid, return it.
                return Some(res);
            } else {
                // Update the metrics.
                self.metrics.invalidated_entries.inc();
                self.metrics
                    .invalidated_entries_duration
                    .observe(value.elapsed_seconds(now));
                // For the sake of correctness, we need a fall-through logic here.
                if !value.is_valid_time(env) {
                    self.metrics.invalidated_entries_by_time.inc();
                }
                if !value.is_valid_canister_version(env) {
                    self.metrics.invalidated_entries_by_canister_version.inc();
                }
                if !value.is_valid_canister_balance(env) {
                    self.metrics.invalidated_entries_by_canister_balance.inc();
                }
                // The cache entry is no longer valid, remove it.
                cache.pop(key);
            }
        }
        None
    }

    pub(crate) fn push(&self, key: EntryKey, value: EntryValue) -> Vec<(EntryKey, EntryValue)> {
        let now = value.env.batch_time;
        let mut cache = self.cache.lock().unwrap();
        let evicted_entries = cache.push(key, value);

        // Update the metrics.
        self.metrics
            .evicted_entries
            .inc_by(evicted_entries.len() as u64);
        for (_evited_key, evicted_value) in &evicted_entries {
            let d = evicted_value.elapsed_seconds(now);
            self.metrics.evicted_entries_duration.observe(d);
        }
        self.metrics.misses.inc();
        let count_bytes = cache.count_bytes() as i64;
        self.metrics.count_bytes.set(count_bytes);
        self.metrics.len.set(cache.len() as i64);

        evicted_entries
    }
}
