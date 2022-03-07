use ic_metrics::MetricsRegistry;
use std::collections::BTreeMap;

use crate::metrics::PoolMetrics;

const MESSAGE_SIZE_BYTES: usize = 0;

/// Wrapper around `BTreeMap`, instrumenting insertions and removals.
pub(crate) struct PoolSection<K, V> {
    messages: BTreeMap<K, V>,
    metrics: PoolMetrics,
}

impl<K: Ord, V> PoolSection<K, V> {
    pub(crate) fn new(metrics_registry: MetricsRegistry, pool: &str, pool_type: &str) -> Self {
        Self {
            messages: Default::default(),
            metrics: PoolMetrics::new(metrics_registry, pool, pool_type),
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.metrics.observe_insert(MESSAGE_SIZE_BYTES);
        let replaced = self.messages.insert(key, value);
        if replaced.is_some() {
            self.metrics.observe_duplicate(MESSAGE_SIZE_BYTES);
        }
        replaced
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.messages.remove(key);
        if removed.is_some() {
            self.metrics.observe_remove(MESSAGE_SIZE_BYTES);
        }
        removed
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.messages.get(key)
    }

    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.messages.contains_key(key)
    }

    pub(crate) fn iter(&self) -> std::collections::btree_map::Iter<'_, K, V> {
        self.messages.iter()
    }

    pub(crate) fn values(&self) -> std::collections::btree_map::Values<'_, K, V> {
        self.messages.values()
    }
}
