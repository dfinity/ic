use ic_base_types::{CanisterId, NumBytes};
use ic_error_types::UserError;
use ic_interfaces::execution_environment::SystemApiCallCounters;
use ic_metrics::MetricsRegistry;
use ic_replicated_state::ReplicatedState;
use ic_types::{ingress::WasmResult, messages::UserQuery, CountBytes, Cycles, Time, UserId};
use ic_utils_lru_cache::LruCache;
use prometheus::{Histogram, IntCounter, IntGauge};
use std::{mem::size_of_val, sync::Mutex, time::Duration};

use crate::metrics::duration_histogram;

#[cfg(test)]
mod tests;

////////////////////////////////////////////////////////////////////////
/// Query Cache metrics.
pub(crate) struct QueryCacheMetrics {
    pub hits: IntCounter,
    pub hits_with_ignored_time: IntCounter,
    pub hits_with_ignored_canister_balance: IntCounter,
    pub misses: IntCounter,
    pub evicted_entries: IntCounter,
    pub evicted_entries_duration: Histogram,
    pub invalidated_entries: IntCounter,
    pub invalidated_entries_by_time: IntCounter,
    pub invalidated_entries_by_max_expiry_time: IntCounter,
    pub invalidated_entries_by_data_certificate_expiry_time: IntCounter,
    pub invalidated_entries_by_canister_version: IntCounter,
    pub invalidated_entries_by_canister_balance: IntCounter,
    pub invalidated_entries_by_nested_call: IntCounter,
    pub invalidated_entries_by_error: IntCounter,
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
            hits_with_ignored_time: metrics_registry.int_counter(
                "execution_query_cache_hits_with_ignored_time_total",
                "The total number of cache hits into entries with ignored time",
            ),
            hits_with_ignored_canister_balance: metrics_registry.int_counter(
                "execution_query_cache_hits_with_ignored_canister_balance_total",
                "The total number of cache hits into entries with ignored canister balance",
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
            invalidated_entries_by_max_expiry_time: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_max_expiry_time_total",
                "The total number of invalidated entries due to the max expiry time",
            ),
            invalidated_entries_by_data_certificate_expiry_time: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_data_certificate_expiry_time_total",
                "The total number of invalidated entries due to the data certificate expiry time",
            ),
            invalidated_entries_by_canister_version: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_canister_version_total",
                "The total number of invalidated entries due to the changed canister version",
            ),
            invalidated_entries_by_canister_balance: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_canister_balance_total",
                "The total number of invalidated entries due to the changed canister balance",
            ),
            invalidated_entries_by_nested_call: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_nested_call_total",
                "The total number of invalidated entries due to a nested call",
            ),
            invalidated_entries_by_error: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_error_total",
                "The total number of invalidated entries due to an error",
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
#[derive(Clone, Eq, Hash, PartialEq)]
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
/// Query Cache entry environment metadata captured before the query execution.
///
/// The cache entry is valid as long as the metadata is unchanged,
/// or it can be proven that the query does not depend on the change.
#[derive(PartialEq)]
pub(crate) struct EntryEnv {
    /// The consensus-determined time when the query is executed.
    pub batch_time: Time,
    /// Receiving canister version (includes both canister updates and upgrades).
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

////////////////////////////////////////////////////////////////////////
/// Query Cache entry value.
pub(crate) struct EntryValue {
    /// Query Cache entry environment metadata captured before the query execution.
    env: EntryEnv,
    /// The result produced by the query.
    result: Result<WasmResult, UserError>,
    /// If set, the cached entry should be expired after `data_certificate_expiry_time`.
    includes_data_certificate: bool,
    /// If set, the `env.batch_time` might be ignored.
    ignore_batch_time: bool,
    /// If set, the `env.canister_balance` might be ignored.
    ignore_canister_balance: bool,
}

impl CountBytes for EntryValue {
    fn count_bytes(&self) -> usize {
        size_of_val(self) + self.result.count_bytes()
    }
}

impl EntryValue {
    pub(crate) fn new(
        env: EntryEnv,
        result: Result<WasmResult, UserError>,
        system_api_call_counters: &SystemApiCallCounters,
    ) -> EntryValue {
        // The cached entry should be expired after `data_certificate_expiry_time`.
        let includes_data_certificate = system_api_call_counters.data_certificate_copy > 0;
        // It's safe to ignore `batch_time` changes if the query never calls `ic0.time()`.
        let ignore_batch_time = system_api_call_counters.time == 0;
        // It's safe to ignore `canister_balance` changes if the query never checks the balance.
        let ignore_canister_balance = system_api_call_counters.canister_cycle_balance == 0
            && system_api_call_counters.canister_cycle_balance128 == 0;
        EntryValue {
            env,
            result,
            includes_data_certificate,
            ignore_batch_time,
            ignore_canister_balance,
        }
    }

    fn is_valid(
        &self,
        env: &EntryEnv,
        max_expiry_time: Duration,
        data_certificate_expiry_time: Duration,
    ) -> bool {
        self.is_valid_time(env)
            && !self.is_expired(env, max_expiry_time)
            && !self.is_expired_data_certificate(env, data_certificate_expiry_time)
            && self.is_valid_canister_version(env)
            && self.is_valid_canister_balance(env)
    }

    fn is_valid_time(&self, env: &EntryEnv) -> bool {
        self.ignore_batch_time || self.env.batch_time == env.batch_time
    }

    /// Check cache entry max expiration time.
    fn is_expired(&self, env: &EntryEnv, max_expiry_time: Duration) -> bool {
        if let Some(duration) = env.batch_time.checked_duration_since(self.env.batch_time) {
            duration > max_expiry_time
        } else {
            false
        }
    }

    /// Check cache entry data certificate expiration time.
    fn is_expired_data_certificate(
        &self,
        env: &EntryEnv,
        data_certificate_expiry_time: Duration,
    ) -> bool {
        if self.includes_data_certificate {
            return self.is_expired(env, data_certificate_expiry_time);
        }
        false
    }

    fn is_valid_canister_version(&self, env: &EntryEnv) -> bool {
        self.env.canister_version == env.canister_version
    }

    fn is_valid_canister_balance(&self, env: &EntryEnv) -> bool {
        self.ignore_canister_balance || self.env.canister_balance == env.canister_balance
    }

    /// Return true if the time difference was ignored.
    fn is_ignored_time(&self, env: &EntryEnv) -> bool {
        self.env.batch_time != env.batch_time && self.ignore_batch_time
    }

    /// Return true if the canister balance difference was ignored.
    fn is_ignored_canister_balance(&self, env: &EntryEnv) -> bool {
        self.env.canister_balance != env.canister_balance && self.ignore_canister_balance
    }

    fn result(&self) -> Result<WasmResult, UserError> {
        self.result.clone()
    }

    fn elapsed_seconds(&self, now: Time) -> f64 {
        now.saturating_duration_since(self.env.batch_time)
            .as_secs_f64()
    }
}

////////////////////////////////////////////////////////////////////////
/// Replica Side Query Cache.
pub(crate) struct QueryCache {
    // We can't use `RwLock`, as the `LruCache::get()` requires mutable reference
    // to update the LRU.
    cache: Mutex<LruCache<EntryKey, EntryValue>>,
    /// The upper limit on how long the cache entry stays valid in the query cache.
    max_expiry_time: Duration,
    /// The upper limit on how long the data certificate stays valid in the query cache.
    data_certificate_expiry_time: Duration,
    /// Query cache metrics (public for tests)
    pub(crate) metrics: QueryCacheMetrics,
}

impl CountBytes for QueryCache {
    fn count_bytes(&self) -> usize {
        size_of_val(self) + self.cache.lock().unwrap().count_bytes()
    }
}

impl QueryCache {
    /// Create a new `QueryCache` instance.
    pub(crate) fn new(
        metrics_registry: &MetricsRegistry,
        capacity: NumBytes,
        max_expiry_time: Duration,
        data_certificate_expiry_time: Duration,
    ) -> Self {
        QueryCache {
            cache: Mutex::new(LruCache::new(capacity)),
            max_expiry_time,
            data_certificate_expiry_time,
            metrics: QueryCacheMetrics::new(metrics_registry),
        }
    }

    /// Return the cached `Result` if it's still valid, updating the metrics.
    pub(crate) fn get_valid_result(
        &self,
        key: &EntryKey,
        env: &EntryEnv,
    ) -> Option<Result<WasmResult, UserError>> {
        let mut cache = self.cache.lock().unwrap();
        let now = env.batch_time;

        if let Some(value) = cache.get(key) {
            if value.is_valid(env, self.max_expiry_time, self.data_certificate_expiry_time) {
                let res = value.result();
                // Update the metrics.
                self.metrics.hits.inc();
                // For the sake of correctness, we need a fall-through logic here.
                if value.is_ignored_time(env) {
                    self.metrics.hits_with_ignored_time.inc();
                }
                if value.is_ignored_canister_balance(env) {
                    self.metrics.hits_with_ignored_canister_balance.inc();
                }
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
                if value.is_expired(env, self.max_expiry_time) {
                    self.metrics.invalidated_entries_by_max_expiry_time.inc();
                }
                if value.is_expired_data_certificate(env, self.data_certificate_expiry_time) {
                    self.metrics
                        .invalidated_entries_by_data_certificate_expiry_time
                        .inc();
                }
                if !value.is_valid_canister_version(env) {
                    self.metrics.invalidated_entries_by_canister_version.inc();
                }
                if !value.is_valid_canister_balance(env) {
                    self.metrics.invalidated_entries_by_canister_balance.inc();
                }
                // The cache entry is no longer valid, remove it.
                cache.pop(key);
                // Update the metrics.
                let count_bytes = cache.count_bytes() as i64;
                self.metrics.count_bytes.set(count_bytes);
            }
        }
        None
    }

    /// Push a new `result` to the cache, evicting LRU entries if needed and updating the metrics.
    pub(crate) fn push(
        &self,
        key: EntryKey,
        env: EntryEnv,
        result: &Result<WasmResult, UserError>,
        system_api_call_counters: &SystemApiCallCounters,
    ) {
        let now = env.batch_time;
        // Push is always a cache miss.
        self.metrics.misses.inc();

        // The result should not be saved if the result is an error.
        // In the future we might distinguish between the transient and
        // permanent errors, but for now we just avoid caching any errors.
        if result.is_err() {
            // Because of the error, the cache entry is immediately invalidated.
            self.metrics.invalidated_entries.inc();
            self.metrics.invalidated_entries_duration.observe(0_f64);
            self.metrics.invalidated_entries_by_error.inc();
            return;
        }

        // The result should not be saved if the query calls a nested query.
        if system_api_call_counters.call_perform != 0 {
            // Because of the nested calls the entry is immediately invalidated.
            self.metrics.invalidated_entries.inc();
            self.metrics.invalidated_entries_duration.observe(0_f64);
            self.metrics.invalidated_entries_by_nested_call.inc();
            return;
        }

        let value = EntryValue::new(env, result.clone(), system_api_call_counters);
        let mut cache = self.cache.lock().unwrap();
        let evicted_entries = cache.push(key, value);

        // Update other metrics.
        self.metrics
            .evicted_entries
            .inc_by(evicted_entries.len() as u64);
        for (_evicted_key, evicted_value) in &evicted_entries {
            let d = evicted_value.elapsed_seconds(now);
            self.metrics.evicted_entries_duration.observe(d);
        }
        let count_bytes = cache.count_bytes() as i64;
        self.metrics.count_bytes.set(count_bytes);
        self.metrics.len.set(cache.len() as i64);
    }
}
