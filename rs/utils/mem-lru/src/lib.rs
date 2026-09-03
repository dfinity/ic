//! A minimal, fixed-capacity, in-memory LRU cache that tracks hit/miss counts.

use std::hash::Hash;

/// A fixed-capacity LRU cache that additionally tracks hit/miss statistics.
///
/// This is a thin wrapper around [`lru::LruCache`], which on its own does not
/// keep hit/miss counters. Reading a present key (via [`Self::get`]) marks it
/// as most-recently-used and counts a hit; a missing key counts a miss. Once
/// the cache is at capacity, inserting a new key evicts the least-recently-used
/// entry.
///
/// # Example
/// ```
/// use ic_utils_mem_lru::LruCacheWithStats;
///
/// let mut cache = LruCacheWithStats::with_size(2);
/// cache.insert("a", 1);
/// cache.insert("b", 2);
/// assert_eq!(cache.get(&"a"), Some(&1)); // hit; marks "a" most-recently-used
/// cache.insert("c", 3); // cache is full, so this evicts "b" (least-recently-used)
/// assert_eq!(cache.get(&"b"), None); // miss; "b" was evicted
/// assert_eq!(cache.len(), 2);
/// assert_eq!(cache.hits(), 1);
/// assert_eq!(cache.misses(), 1);
/// ```
pub struct LruCacheWithStats<K, V> {
    cache: lru::LruCache<K, V>,
    hits: u64,
    misses: u64,
}

impl<K: Eq + Hash, V> LruCacheWithStats<K, V> {
    /// Create a new cache holding at most `max_size` entries.
    pub fn with_size(max_size: usize) -> Self {
        Self {
            cache: lru::LruCache::new(max_size),
            hits: 0,
            misses: 0,
        }
    }

    /// Return a borrow of the value cached for `key`, marking it
    /// most-recently-used, while recording a hit or a miss.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let value = self.cache.get(key);
        if value.is_some() {
            self.hits += 1;
        } else {
            self.misses += 1;
        }
        value
    }

    /// Insert `value` for `key`, evicting the least-recently-used entry if the
    /// cache is at capacity.
    pub fn insert(&mut self, key: K, value: V) {
        self.cache.put(key, value);
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns `true` if the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.cache.len() == 0
    }

    /// Number of hits recorded by [`Self::get`].
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Number of misses recorded by [`Self::get`].
    pub fn misses(&self) -> u64 {
        self.misses
    }
}

impl<K: Eq + Hash, V: Clone> LruCacheWithStats<K, V> {
    /// Like [`Self::get`], but returns an owned clone of the value rather
    /// than a borrow. Useful when the caller needs to retain the value
    /// beyond the cache's borrow, e.g. after releasing a lock guard on the
    /// cache.
    pub fn get_cloned(&mut self, key: &K) -> Option<V> {
        self.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::LruCacheWithStats;

    #[test]
    fn counts_hits_and_misses() {
        let mut cache = LruCacheWithStats::with_size(4);
        assert_eq!(cache.get(&1), None); // miss
        cache.insert(1, "a");
        assert_eq!(cache.get(&1), Some(&"a")); // hit
        assert_eq!(cache.get(&1), Some(&"a")); // hit
        assert_eq!(cache.get(&2), None); // miss
        assert_eq!(cache.hits(), 2);
        assert_eq!(cache.misses(), 2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn evicts_least_recently_used() {
        let mut cache = LruCacheWithStats::with_size(2);
        cache.insert(1, "a");
        cache.insert(2, "b");
        // Touch key 1 so that key 2 becomes the least-recently-used entry.
        assert_eq!(cache.get(&1), Some(&"a"));
        cache.insert(3, "c"); // evicts key 2
        assert_eq!(cache.get(&2), None);
        assert_eq!(cache.get(&1), Some(&"a"));
        assert_eq!(cache.get(&3), Some(&"c"));
        assert_eq!(cache.hits(), 3);
        assert_eq!(cache.misses(), 1);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn is_empty_reflects_len() {
        let mut cache = LruCacheWithStats::with_size(1);
        assert!(cache.is_empty());
        cache.insert(1, ());
        assert!(!cache.is_empty());
    }
}
