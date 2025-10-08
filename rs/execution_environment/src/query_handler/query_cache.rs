use ic_base_types::{CanisterId, NumBytes};
use ic_error_types::UserError;
use ic_heap_bytes::{DeterministicHeapBytes, HeapBytes, total_bytes};
use ic_interfaces::execution_environment::SystemApiCallCounters;
use ic_metrics::MetricsRegistry;
use ic_query_stats::QueryStatsCollector;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    Cycles, DiskBytes, Time, UserId,
    batch::QueryStats,
    ingress::WasmResult,
    messages::{CertificateDelegationFormat, CertificateDelegationMetadata, Query},
};
use ic_utils_lru_cache::LruCache;
use prometheus::{Histogram, IntCounter, IntGauge};
use std::{collections::BTreeMap, sync::Mutex, time::Duration};

use crate::metrics::duration_histogram;

#[cfg(test)]
mod tests;

////////////////////////////////////////////////////////////////////////
/// Query Cache metrics.
#[derive(HeapBytes)]
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
    pub invalidated_entries_by_transient_error: IntCounter,
    pub invalidated_entries_duration: Histogram,
    pub count_bytes: IntGauge,
    pub len: IntGauge,
    pub push_errors: IntCounter,
    pub validation_errors: IntCounter,
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
            invalidated_entries_by_transient_error: metrics_registry.int_counter(
                "execution_query_cache_invalidated_entries_by_transient_error_total",
                "The total number of invalidated entries due to a transient error",
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
            push_errors: metrics_registry.int_counter(
                "execution_query_cache_push_errors_total",
                "The total number of errors adding new query cache entries",
            ),
            validation_errors: metrics_registry.int_counter(
                "execution_query_cache_validation_errors_total",
                "The total number of errors validating query cache entries",
            ),
        }
    }
}

////////////////////////////////////////////////////////////////////////
/// Query Cache entry key.
///
/// The key is to distinguish query cache entries, i.e. entries with different
/// keys are (almost) completely independent from each other.
#[derive(Clone, DeterministicHeapBytes, Eq, PartialEq, Hash)]
pub(crate) struct EntryKey {
    /// Query source.
    pub source: UserId,
    /// Query receiving canister (destination).
    pub receiver: CanisterId,
    /// Receiving canister method name.
    pub method_name: String,
    /// Receiving canister method payload (argument).
    pub method_payload: Vec<u8>,
    /// Format of the certificate delegation.
    pub certificate_delegation_format: Option<CertificateDelegationFormat>,
}

impl EntryKey {
    pub fn new(
        query: &Query,
        certificate_delegation_metadata: Option<CertificateDelegationMetadata>,
    ) -> Self {
        Self {
            source: query.source.user_id(),
            receiver: query.receiver,
            method_name: query.method_name.clone(),
            method_payload: query.method_payload.clone(),
            certificate_delegation_format: certificate_delegation_metadata
                .map(|metadata| metadata.format),
        }
    }
}

impl DiskBytes for EntryKey {}

////////////////////////////////////////////////////////////////////////
/// Query Cache entry environment metadata captured before the query execution.
///
/// The cache entry is valid as long as the metadata is unchanged,
/// or it can be proven that the query does not depend on the change.
#[derive(DeterministicHeapBytes, PartialEq)]
pub(crate) struct EntryEnv {
    /// The consensus-determined time when the query is executed.
    pub batch_time: Time,
    /// A vector of evaluated canister IDs with their versions, balances and stats.
    pub canisters_versions_balances_stats: Vec<(CanisterId, u64, Cycles, QueryStats)>,
}

impl EntryEnv {
    // Capture a state (canister version and balance) of the evaluated canisters.
    fn try_new(
        state: &ReplicatedState,
        evaluated_stats: &BTreeMap<CanisterId, QueryStats>,
    ) -> Result<Self, UserError> {
        let mut canisters_versions_balances_stats = Vec::with_capacity(evaluated_stats.len());
        for (id, stats) in evaluated_stats.iter() {
            let canister = state.get_active_canister(id)?;
            canisters_versions_balances_stats.push((
                *id,
                canister.system_state.canister_version,
                canister.system_state.balance(),
                stats.clone(),
            ));
        }
        Ok(EntryEnv {
            batch_time: state.metadata.batch_time,
            canisters_versions_balances_stats,
        })
    }
}

////////////////////////////////////////////////////////////////////////
/// Query Cache entry value.
#[derive(DeterministicHeapBytes)]
pub(crate) struct EntryValue {
    /// Query Cache entry environment metadata captured before the query execution.
    env: EntryEnv,
    /// The result produced by the query.
    result: Result<WasmResult, UserError>,
    /// If set, the cached entry should be expired after `data_certificate_expiry_time`.
    includes_data_certificate: bool,
    /// If set, the batch time changes might be ignored.
    ignore_batch_time: bool,
    /// If set, the canister balance changes might be ignored.
    ignore_canister_balances: bool,
}

impl DiskBytes for EntryValue {}

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
        let ignore_canister_balances = system_api_call_counters.canister_cycle_balance == 0
            && system_api_call_counters.canister_cycle_balance128 == 0;
        EntryValue {
            env,
            result,
            includes_data_certificate,
            ignore_batch_time,
            ignore_canister_balances,
        }
    }

    fn is_valid(
        &self,
        state: &ReplicatedState,
        query_stats_collector: Option<&QueryStatsCollector>,
        metrics: &QueryCacheMetrics,
        max_expiry_time: Duration,
        data_certificate_expiry_time: Duration,
    ) -> bool {
        // Iterate over the captured data and validate it against the current state.
        let mut all_canister_versions_are_valid = true;
        let mut all_canister_balances_are_valid = true;
        let mut canisters_stats =
            Vec::with_capacity(self.env.canisters_versions_balances_stats.len());
        for (id, version, balance, stats) in &self.env.canisters_versions_balances_stats {
            let Ok(canister) = state.get_active_canister(id) else {
                metrics.validation_errors.inc();
                return false;
            };
            canisters_stats.push((id, stats));

            if &canister.system_state.canister_version != version {
                all_canister_versions_are_valid = false;
            }
            if &canister.system_state.balance() != balance {
                all_canister_balances_are_valid = false;
            }
        }

        // Validate the rest of the cached value.
        let now = state.metadata.batch_time;
        let is_expired = self.is_expired(now, max_expiry_time);
        let is_expired_data_certificate =
            self.is_expired_data_certificate(now, data_certificate_expiry_time);

        // Check if the cache entry value is valid.
        if !is_expired
            && !is_expired_data_certificate
            && (self.env.batch_time == now || self.ignore_batch_time)
            && all_canister_versions_are_valid
            && (all_canister_balances_are_valid || self.ignore_canister_balances)
        {
            // The value is still valid.
            metrics.hits.inc();
            // Apply query stats.
            for (id, stats) in canisters_stats {
                // Add query statistics to the query aggregator.
                if let Some(query_stats_collector) = query_stats_collector {
                    query_stats_collector.register_query_statistics(*id, stats);
                }
            }
            // Several factors might cause ignoring behavior simultaneously.
            // To ensure correctness, we need a fallthrough logic here.
            if self.env.batch_time != now && self.ignore_batch_time {
                metrics.hits_with_ignored_time.inc();
            }
            if !all_canister_balances_are_valid && self.ignore_canister_balances {
                metrics.hits_with_ignored_canister_balance.inc();
            }
            true
        } else {
            // The value is invalid.
            metrics.invalidated_entries.inc();
            metrics
                .invalidated_entries_duration
                .observe(self.elapsed_seconds(now));
            // To ensure all invalidation reasons are accounted for,
            // even if multiple occur simultaneously, we need a fallthrough logic here.
            if is_expired {
                metrics.invalidated_entries_by_max_expiry_time.inc();
            }
            if is_expired_data_certificate {
                metrics
                    .invalidated_entries_by_data_certificate_expiry_time
                    .inc();
            }
            if !(self.env.batch_time == now || self.ignore_batch_time) {
                metrics.invalidated_entries_by_time.inc();
            }
            if !all_canister_versions_are_valid {
                metrics.invalidated_entries_by_canister_version.inc();
            }
            if !(all_canister_balances_are_valid || self.ignore_canister_balances) {
                metrics.invalidated_entries_by_canister_balance.inc();
            }
            false
        }
    }

    /// Check cache entry max expiration time.
    fn is_expired(&self, now: Time, max_expiry_time: Duration) -> bool {
        if let Some(duration) = now.checked_duration_since(self.env.batch_time) {
            duration > max_expiry_time
        } else {
            false
        }
    }

    /// Check cache entry data certificate expiration time.
    ///
    /// When we track the query execution, any `ic0.data_certificate_copy`
    /// System API call will set the `includes_data_certificate` flag in
    /// the cached value.
    ///
    /// Just like the system time, we don't need to track it per-canister.
    /// If any of the canisters in the call graph read the certificate,
    /// the whole cached result will be expired sooner. But it just depends
    /// on the system time, not the canister state.
    fn is_expired_data_certificate(
        &self,
        now: Time,
        data_certificate_expiry_time: Duration,
    ) -> bool {
        if self.includes_data_certificate {
            return self.is_expired(now, data_certificate_expiry_time);
        }
        false
    }

    fn elapsed_seconds(&self, now: Time) -> f64 {
        now.saturating_duration_since(self.env.batch_time)
            .as_secs_f64()
    }
}

////////////////////////////////////////////////////////////////////////
/// Replica Side Query Cache.
#[derive(HeapBytes)]
pub(crate) struct QueryCache {
    // We can't use `RwLock`, as the `LruCache::get()` requires mutable reference
    // to update the LRU.
    cache: Mutex<LruCache<EntryKey, EntryValue>>,
    /// The upper limit on how long the cache entry stays valid in the query cache.
    max_expiry_time: Duration,
    /// The upper limit on how long the data certificate stays valid in the query cache.
    data_certificate_expiry_time: Duration,
    /// Query cache metrics (public for tests).
    pub(crate) metrics: QueryCacheMetrics,
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
            cache: Mutex::new(LruCache::new(capacity, NumBytes::from(0))),
            max_expiry_time,
            data_certificate_expiry_time,
            metrics: QueryCacheMetrics::new(metrics_registry),
        }
    }

    /// Return the cached `Result` if it's still valid, updating the metrics and stats.
    pub(crate) fn get_valid_result(
        &self,
        key: &EntryKey,
        state: &ReplicatedState,
        query_stats_collector: Option<&QueryStatsCollector>,
    ) -> Option<Result<WasmResult, UserError>> {
        let mut cache = self.cache.lock().unwrap();

        if let Some(value) = cache.get(key) {
            if value.is_valid(
                state,
                query_stats_collector,
                &self.metrics,
                self.max_expiry_time,
                self.data_certificate_expiry_time,
            ) {
                // The cache entry is valid, return it.
                return Some(value.result.clone());
            } else {
                // The cache entry is no longer valid, remove it.
                cache.pop(key);
                // Update the `count_bytes` metric.
                self.metrics.count_bytes.set(total_bytes(&*cache) as i64);
            }
        }
        None
    }

    /// Push a new `result` to the cache, evicting LRU entries if needed and updating the metrics.
    pub(crate) fn push(
        &self,
        key: EntryKey,
        result: &Result<WasmResult, UserError>,
        state: &ReplicatedState,
        system_api_counters: &SystemApiCallCounters,
        evaluated_stats: &BTreeMap<CanisterId, QueryStats>,
        transient_errors: usize,
    ) {
        let now = state.metadata.batch_time;
        // Push is always a cache miss.
        self.metrics.misses.inc();

        // The result should not be saved if there were transient errors.
        if transient_errors > 0 {
            // Because of the transient error, the cache entry is immediately invalidated.
            self.metrics.invalidated_entries.inc();
            self.metrics.invalidated_entries_duration.observe(0_f64);
            self.metrics.invalidated_entries_by_transient_error.inc();
            return;
        }

        // This can fail only if there is no active canister ID,
        // which should not happen, as we just evaluated those canisters.
        let Ok(env) = EntryEnv::try_new(state, evaluated_stats) else {
            self.metrics.push_errors.inc();
            return;
        };

        let value = EntryValue::new(env, result.clone(), system_api_counters);
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
        let memory_bytes = total_bytes(&*cache) as i64;
        self.metrics.count_bytes.set(memory_bytes);
        self.metrics.len.set(cache.len() as i64);
    }
}
