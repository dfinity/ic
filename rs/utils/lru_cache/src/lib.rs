use ic_types::NumBytes;
use std::hash::Hash;

/// The upper bound on cache item size and cache capacity.
/// It is needed to ensure that all arithmetic operations
/// do not overflow.
const MAX_SIZE: NumBytes = NumBytes::new(u64::MAX / 2);

/// A cache with bounded memory capacity that evicts items using the
/// least-recently used eviction policy. It guarantees that the sum of
/// sizes of the cached items does not exceed the pre-configured capacity.
pub struct LruCache<K, V>
where
    K: Eq + Hash,
{
    cache: lru::LruCache<K, (V, NumBytes)>,
    capacity: NumBytes,
    size: NumBytes,
}

impl<K, V> LruCache<K, V>
where
    K: Eq + Hash,
{
    /// Constructs a new LRU cache with the given capacity.
    /// The capacity must not exceed `MAX_SIZE = (2^63 - 1)`.
    pub fn new(capacity: NumBytes) -> Self {
        assert!(capacity <= MAX_SIZE);
        let lru_cache = Self {
            cache: lru::LruCache::unbounded(),
            capacity,
            size: NumBytes::new(0),
        };
        lru_cache.check_invariants();
        lru_cache
    }

    /// Returns the value corresponding to the given key.
    /// It also marks the item as the most-recently used.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.cache.get(key).map(|(value, _size)| value)
    }

    /// Inserts or updates the item with the given key.
    /// It also marks the item as the most-recently used.
    /// The size parameter specifies the size of the item,
    /// which must not exceed `MAX_SIZE = (2^63 - 1)`.
    pub fn put(&mut self, key: K, value: V, size: NumBytes) {
        assert!(size <= MAX_SIZE);
        if let Some((_, prev_size)) = self.cache.put(key, (value, size)) {
            debug_assert!(self.size >= prev_size);
            // This cannot underflow because we know that `self.size` is
            // the sum of sizes of all items in the cache.
            self.size -= prev_size;
        }
        // This cannot overflow because we know that
        // `self.size <= self.capacity <= MAX_SIZE`
        // and `size <= MAX_SIZE == u64::MAX / 2`.
        self.size += size;
        self.evict();
        self.check_invariants();
    }

    /// Clears the cache by removing all items.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.size = NumBytes::new(0);
        self.check_invariants();
    }

    /// Evicts as many items as needed to restore the capacity guarantee.
    fn evict(&mut self) {
        while self.size > self.capacity {
            match self.cache.pop_lru() {
                Some((_k, (_v, size))) => {
                    debug_assert!(self.size >= size);
                    // This cannot underflow because we know that `self.size` is
                    // the sum of sizes of all items in the cache.
                    self.size -= size;
                }
                None => break,
            }
        }
    }

    fn check_invariants(&self) {
        debug_assert_eq!(self.size, self.cache.iter().map(|(_k, (_v, s))| *s).sum());
        debug_assert!(self.size <= self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_cache_single_entry() {
        let mut lru = LruCache::<u32, u32>::new(NumBytes::new(10));

        assert!(lru.get(&0).is_none());

        lru.put(0, 42, NumBytes::new(10));
        assert_eq!(*lru.get(&0).unwrap(), 42);

        lru.put(0, 42, NumBytes::new(11));
        assert!(lru.get(&0).is_none());

        lru.put(0, 24, NumBytes::new(10));
        assert_eq!(*lru.get(&0).unwrap(), 24);
    }

    #[test]
    fn lru_cache_multiple_entries() {
        let mut lru = LruCache::<u32, u32>::new(NumBytes::new(10));

        for i in 0..20 {
            lru.put(i, i, NumBytes::new(1));
        }

        for i in 0..20 {
            let result = lru.get(&i);
            if i < 10 {
                assert!(result.is_none());
            } else {
                assert_eq!(*result.unwrap(), i);
            }
        }
    }

    #[test]
    fn lru_cache_eviction() {
        let mut lru = LruCache::<u32, u32>::new(NumBytes::new(10));

        assert!(lru.get(&0).is_none());

        lru.put(0, 42, NumBytes::new(10));
        assert_eq!(*lru.get(&0).unwrap(), 42);

        lru.put(1, 20, NumBytes::new(0));
        assert_eq!(*lru.get(&0).unwrap(), 42);
        assert_eq!(*lru.get(&1).unwrap(), 20);

        lru.put(2, 10, NumBytes::new(10));
        assert!(lru.get(&0).is_none());
        assert_eq!(*lru.get(&1).unwrap(), 20);
        assert_eq!(*lru.get(&2).unwrap(), 10);

        lru.put(3, 30, NumBytes::new(10));
        assert!(lru.get(&1).is_none());
        assert!(lru.get(&2).is_none());
        assert_eq!(*lru.get(&3).unwrap(), 30);

        lru.put(3, 60, NumBytes::new(5));
        assert_eq!(*lru.get(&3).unwrap(), 60);

        lru.put(4, 40, NumBytes::new(5));
        assert_eq!(*lru.get(&3).unwrap(), 60);
        assert_eq!(*lru.get(&4).unwrap(), 40);

        lru.put(4, 40, NumBytes::new(10));
        assert!(lru.get(&3).is_none());
        assert_eq!(*lru.get(&4).unwrap(), 40);
    }

    #[test]
    fn lru_cache_clear() {
        let mut lru = LruCache::<u32, u32>::new(NumBytes::new(10));
        lru.put(0, 0, NumBytes::new(10));
        lru.clear();
        assert!(lru.get(&0).is_none());
    }
}
