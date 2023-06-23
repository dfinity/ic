use ic_types::{CountBytes, NumBytes};
use std::hash::Hash;

/// The upper bound on cache item size and cache capacity.
/// It is needed to ensure that all arithmetic operations
/// do not overflow.
const MAX_SIZE: usize = usize::MAX / 2;

/// A cache with bounded memory capacity that evicts items using the
/// least-recently used eviction policy. It guarantees that the sum of
/// sizes of the cached items does not exceed the pre-configured capacity.
pub struct LruCache<K, V>
where
    K: CountBytes + Eq + Hash,
    V: CountBytes,
{
    cache: lru::LruCache<K, V>,
    capacity: usize,
    size: usize,
}

impl<K, V> CountBytes for LruCache<K, V>
where
    K: CountBytes + Eq + Hash,
    V: CountBytes,
{
    fn count_bytes(&self) -> usize {
        self.size
    }
}

impl<K, V> LruCache<K, V>
where
    K: CountBytes + Eq + Hash,
    V: CountBytes,
{
    /// Constructs a new LRU cache with the given capacity.
    /// The capacity must not exceed `MAX_SIZE = (2^63 - 1)`.
    pub fn new(capacity: NumBytes) -> Self {
        let capacity = capacity.get() as usize;
        assert!(capacity <= MAX_SIZE);
        let lru_cache = Self {
            cache: lru::LruCache::unbounded(),
            capacity,
            size: 0,
        };
        lru_cache.check_invariants();
        lru_cache
    }

    /// Creates a new LRU Cache that never automatically evicts items.
    pub fn unbounded() -> Self {
        Self::new(NumBytes::new(MAX_SIZE as u64))
    }

    /// Returns the value corresponding to the given key.
    /// It also marks the item as the most-recently used.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.cache.get(key)
    }

    /// Pushes a key-value pair into the cache. If an entry with key `k` already exists in
    /// the cache or other cache entries are evicted (due to the cache capacity),
    /// then it returns the old entry's key-value pairs. Otherwise, returns an empty vector.
    pub fn push(&mut self, key: K, value: V) -> Vec<(K, V)> {
        let size = key.count_bytes() + value.count_bytes();
        assert!(size <= MAX_SIZE);

        let removed_entry = self.cache.push(key, value);
        if let Some((removed_key, removed_value)) = &removed_entry {
            let removed_size = removed_key.count_bytes() + removed_value.count_bytes();
            debug_assert!(self.size >= removed_size);
            // This cannot underflow because we know that `self.size` is
            // the sum of sizes of all items in the cache.
            self.size -= removed_size;
        }
        // This cannot overflow because we know that
        // `self.size <= self.capacity <= MAX_SIZE`
        // and `size <= MAX_SIZE == usize::MAX / 2`.
        self.size += size;
        let mut evicted_entries = self.evict();
        self.check_invariants();

        evicted_entries.extend(removed_entry);
        evicted_entries
    }

    /// Removes and returns the value corresponding to the key from the cache or
    /// `None` if it does not exist.
    pub fn pop(&mut self, key: &K) -> Option<V> {
        if let Some((key, value)) = self.cache.pop_entry(key) {
            let size = key.count_bytes() + value.count_bytes();
            debug_assert!(self.size >= size);
            self.size -= size;
            self.check_invariants();
            Some(value)
        } else {
            None
        }
    }

    /// Clears the cache by removing all items.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.size = 0;
        self.check_invariants();
    }

    /// Returns the number of key-value pairs that are currently in the the cache.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns a bool indicating whether the cache is empty or not.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Evicts as many items as needed to restore the capacity guarantee.
    /// Returns the vector of evicted key-value pairs.
    fn evict(&mut self) -> Vec<(K, V)> {
        let mut ret = vec![];
        while self.size > self.capacity {
            match self.cache.pop_lru() {
                Some((key, value)) => {
                    let size = key.count_bytes() + value.count_bytes();
                    debug_assert!(self.size >= size);
                    // This cannot underflow because we know that `self.size` is
                    // the sum of sizes of all items in the cache.
                    self.size -= size;

                    ret.push((key, value));
                }
                None => break,
            }
        }
        ret
    }

    fn check_invariants(&self) {
        debug_assert_eq!(
            self.size,
            self.cache
                .iter()
                .map(|(key, value)| key.count_bytes() + value.count_bytes())
                .sum::<usize>()
        );
        debug_assert!(self.size <= self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, Hash, PartialEq)]
    struct ValueSize(u32, usize);

    impl CountBytes for ValueSize {
        fn count_bytes(&self) -> usize {
            self.1
        }
    }

    #[derive(Debug, Eq, Hash, PartialEq)]
    struct Key(u32);

    impl CountBytes for Key {
        fn count_bytes(&self) -> usize {
            0
        }
    }

    #[test]
    fn lru_cache_single_entry() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10));

        assert!(lru.get(&Key(0)).is_none());

        let evicted = lru.push(Key(0), ValueSize(42, 10));
        assert_eq!(*lru.get(&Key(0)).unwrap(), ValueSize(42, 10));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(Key(0), ValueSize(42, 11));
        assert!(lru.get(&Key(0)).is_none());
        // The new entry does not fit into the cache.
        assert_eq!(
            evicted,
            vec![(Key(0), ValueSize(42, 11)), (Key(0), ValueSize(42, 10))]
        );

        let evicted = lru.push(Key(0), ValueSize(24, 10));
        assert_eq!(*lru.get(&Key(0)).unwrap(), ValueSize(24, 10));
        assert_eq!(evicted, vec![]);
    }

    #[test]
    fn lru_cache_multiple_entries() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10));

        for i in 0..20 {
            lru.push(Key(i), ValueSize(i, 1));
        }

        for i in 0..20 {
            let result = lru.get(&Key(i));
            if i < 10 {
                assert!(result.is_none());
            } else {
                assert_eq!(*result.unwrap(), ValueSize(i, 1));
            }
        }
    }

    #[test]
    fn lru_cache_value_eviction() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10));

        assert!(lru.get(&Key(0)).is_none());

        let evicted = lru.push(Key(0), ValueSize(42, 10));
        assert_eq!(*lru.get(&Key(0)).unwrap(), ValueSize(42, 10));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(Key(1), ValueSize(20, 0));
        assert_eq!(*lru.get(&Key(0)).unwrap(), ValueSize(42, 10));
        assert_eq!(*lru.get(&Key(1)).unwrap(), ValueSize(20, 0));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(Key(2), ValueSize(10, 10));
        assert!(lru.get(&Key(0)).is_none());
        assert_eq!(*lru.get(&Key(1)).unwrap(), ValueSize(20, 0));
        assert_eq!(*lru.get(&Key(2)).unwrap(), ValueSize(10, 10));
        // The least recently used is the first entry.
        assert_eq!(evicted, vec![(Key(0), ValueSize(42, 10))]);

        let evicted = lru.push(Key(3), ValueSize(30, 10));
        assert!(lru.get(&Key(1)).is_none());
        assert!(lru.get(&Key(2)).is_none());
        assert_eq!(*lru.get(&Key(3)).unwrap(), ValueSize(30, 10));
        // Now the second and third entries are evicted.
        assert_eq!(
            evicted,
            vec![(Key(1), ValueSize(20, 0)), (Key(2), ValueSize(10, 10))]
        );

        let evicted = lru.push(Key(3), ValueSize(60, 5));
        assert_eq!(*lru.get(&Key(3)).unwrap(), ValueSize(60, 5));
        assert_eq!(evicted, vec![(Key(3), ValueSize(30, 10))]);

        let evicted = lru.push(Key(4), ValueSize(40, 5));
        assert_eq!(*lru.get(&Key(3)).unwrap(), ValueSize(60, 5));
        assert_eq!(*lru.get(&Key(4)).unwrap(), ValueSize(40, 5));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(Key(4), ValueSize(40, 10));
        assert!(lru.get(&Key(3)).is_none());
        assert_eq!(*lru.get(&Key(4)).unwrap(), ValueSize(40, 10));
        assert_eq!(
            evicted,
            vec![(Key(3), ValueSize(60, 5)), (Key(4), ValueSize(40, 5))]
        );
    }

    #[test]
    fn lru_cache_key_eviction() {
        let mut lru = LruCache::<ValueSize, ValueSize>::new(NumBytes::new(10));

        assert!(lru.get(&ValueSize(0, 10)).is_none());

        let evicted = lru.push(ValueSize(0, 10), ValueSize(42, 0));
        assert_eq!(*lru.get(&ValueSize(0, 10)).unwrap(), ValueSize(42, 0));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(ValueSize(1, 0), ValueSize(20, 0));
        assert_eq!(*lru.get(&ValueSize(0, 10)).unwrap(), ValueSize(42, 0));
        assert_eq!(*lru.get(&ValueSize(1, 0)).unwrap(), ValueSize(20, 0));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(ValueSize(2, 10), ValueSize(10, 0));
        assert!(lru.get(&ValueSize(0, 10)).is_none());
        assert_eq!(*lru.get(&ValueSize(1, 0)).unwrap(), ValueSize(20, 0));
        assert_eq!(*lru.get(&ValueSize(2, 10)).unwrap(), ValueSize(10, 0));
        // The least recently used is the first entry.
        assert_eq!(evicted, vec![(ValueSize(0, 10), ValueSize(42, 0))]);

        let evicted = lru.push(ValueSize(3, 10), ValueSize(30, 0));
        assert!(lru.get(&ValueSize(1, 0)).is_none());
        assert!(lru.get(&ValueSize(2, 10)).is_none());
        assert_eq!(*lru.get(&ValueSize(3, 10)).unwrap(), ValueSize(30, 0));
        // Now the second and third entries are evicted.
        assert_eq!(
            evicted,
            vec![
                (ValueSize(1, 0), ValueSize(20, 0)),
                (ValueSize(2, 10), ValueSize(10, 0))
            ]
        );

        let evicted = lru.push(ValueSize(3, 5), ValueSize(60, 0));
        assert_eq!(*lru.get(&ValueSize(3, 5)).unwrap(), ValueSize(60, 0));
        assert_eq!(evicted, vec![(ValueSize(3, 10), ValueSize(30, 0))]);

        let evicted = lru.push(ValueSize(4, 5), ValueSize(40, 0));
        assert_eq!(*lru.get(&ValueSize(3, 5)).unwrap(), ValueSize(60, 0));
        assert_eq!(*lru.get(&ValueSize(4, 5)).unwrap(), ValueSize(40, 0));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(ValueSize(4, 10), ValueSize(40, 0));
        assert!(lru.get(&ValueSize(3, 5)).is_none());
        assert_eq!(*lru.get(&ValueSize(4, 10)).unwrap(), ValueSize(40, 0));
        assert_eq!(
            evicted,
            vec![
                (ValueSize(3, 5), ValueSize(60, 0)),
                (ValueSize(4, 5), ValueSize(40, 0))
            ]
        );
    }

    #[test]
    fn lru_cache_key_and_value_eviction() {
        let mut lru = LruCache::<ValueSize, ValueSize>::new(NumBytes::new(10));

        let evicted = lru.push(ValueSize(0, 5), ValueSize(42, 5));
        assert_eq!(*lru.get(&ValueSize(0, 5)).unwrap(), ValueSize(42, 5));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(ValueSize(1, 0), ValueSize(20, 0));
        assert_eq!(*lru.get(&ValueSize(0, 5)).unwrap(), ValueSize(42, 5));
        assert_eq!(*lru.get(&ValueSize(1, 0)).unwrap(), ValueSize(20, 0));
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(ValueSize(2, 5), ValueSize(10, 5));
        assert!(lru.get(&ValueSize(0, 5)).is_none());
        assert_eq!(*lru.get(&ValueSize(1, 0)).unwrap(), ValueSize(20, 0));
        assert_eq!(*lru.get(&ValueSize(2, 5)).unwrap(), ValueSize(10, 5));
        // The least recently used is the first entry.
        assert_eq!(evicted, vec![(ValueSize(0, 5), ValueSize(42, 5))]);

        let evicted = lru.push(ValueSize(3, 5), ValueSize(30, 5));
        assert!(lru.get(&ValueSize(1, 0)).is_none());
        assert!(lru.get(&ValueSize(2, 5)).is_none());
        assert_eq!(*lru.get(&ValueSize(3, 5)).unwrap(), ValueSize(30, 5));
        // Now the second and third entries are evicted.
        assert_eq!(
            evicted,
            vec![
                (ValueSize(1, 0), ValueSize(20, 0)),
                (ValueSize(2, 5), ValueSize(10, 5))
            ]
        );
    }

    #[test]
    fn lru_cache_clear() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10));
        lru.push(Key(0), ValueSize(0, 10));
        lru.clear();
        assert!(lru.get(&Key(0)).is_none());
    }

    #[test]
    fn lru_cache_pop() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10));
        lru.push(Key(0), ValueSize(0, 5));
        lru.push(Key(1), ValueSize(1, 5));
        lru.pop(&Key(0));
        assert!(lru.get(&Key(0)).is_none());
        assert!(lru.get(&Key(1)).is_some());
        lru.pop(&Key(1));
        assert!(lru.get(&Key(1)).is_none());
    }

    #[test]
    fn lru_cache_count_bytes_and_len() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10));
        assert_eq!(0, lru.count_bytes());
        assert_eq!(0, lru.len());
        assert!(lru.is_empty());
        lru.push(Key(0), ValueSize(0, 4));
        assert_eq!(4, lru.count_bytes());
        assert_eq!(1, lru.len());
        assert!(!lru.is_empty());
        lru.push(Key(1), ValueSize(1, 6));
        assert_eq!(10, lru.count_bytes());
        assert_eq!(2, lru.len());
        assert!(!lru.is_empty());
        lru.pop(&Key(0));
        assert_eq!(6, lru.count_bytes());
        assert_eq!(1, lru.len());
        assert!(!lru.is_empty());
        lru.pop(&Key(1));
        assert_eq!(0, lru.count_bytes());
        assert_eq!(0, lru.len());
        assert!(lru.is_empty());
    }
}
