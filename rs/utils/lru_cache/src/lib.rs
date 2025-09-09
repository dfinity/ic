use ic_heap_bytes::DeterministicHeapBytes;
use ic_types::{DiskBytes, NumBytes};
use std::hash::Hash;

/// The upper bound on cache item size and cache capacity.
/// It is needed to ensure that all arithmetic operations
/// do not overflow.
const MAX_SIZE: usize = usize::MAX / 2;

/// A cache with bounded memory capacity that evicts items using the
/// least-recently used eviction policy. It guarantees that the sum of
/// sizes of the cached items does not exceed the pre-configured capacity.
#[derive(DeterministicHeapBytes)]
pub struct LruCache<K, V>
where
    K: DeterministicHeapBytes + DiskBytes + Eq + Hash,
    V: DeterministicHeapBytes + DiskBytes,
{
    #[deterministic_heap_bytes(with = |_| self.memory_size)]
    cache: lru::LruCache<K, V>,
    memory_capacity: usize,
    disk_capacity: usize,
    memory_size: usize,
    disk_size: usize,
}

impl<K, V> DiskBytes for LruCache<K, V>
where
    K: DeterministicHeapBytes + DiskBytes + Eq + Hash,
    V: DeterministicHeapBytes + DiskBytes,
{
    fn disk_bytes(&self) -> usize {
        self.disk_size
    }
}

impl<K, V> LruCache<K, V>
where
    K: DeterministicHeapBytes + DiskBytes + Eq + Hash,
    V: DeterministicHeapBytes + DiskBytes,
{
    /// Constructs a new LRU cache with the given memory and disk capacity.  The
    /// capacities must not exceed `MAX_SIZE = (2^63 - 1)`.
    pub fn new(memory_capacity: NumBytes, disk_capacity: NumBytes) -> Self {
        let memory_capacity = memory_capacity.get() as usize;
        let disk_capacity = disk_capacity.get() as usize;
        assert!(memory_capacity <= MAX_SIZE);
        assert!(disk_capacity <= MAX_SIZE);
        let lru_cache = Self {
            cache: lru::LruCache::unbounded(),
            memory_capacity,
            disk_capacity,
            memory_size: 0,
            disk_size: 0,
        };
        lru_cache.check_invariants();
        lru_cache
    }

    /// Creates a new LRU Cache that never automatically evicts items.
    pub fn unbounded() -> Self {
        Self::new(
            NumBytes::new(MAX_SIZE as u64),
            NumBytes::new(MAX_SIZE as u64),
        )
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
        let memory_size = key.deterministic_heap_bytes() + value.deterministic_heap_bytes();
        assert!(memory_size <= MAX_SIZE);
        let disk_size = key.disk_bytes() + value.disk_bytes();
        assert!(disk_size <= MAX_SIZE);

        let removed_entry = self.cache.push(key, value);
        if let Some((removed_key, removed_value)) = &removed_entry {
            self.pop_inner(removed_key, removed_value);
        }
        // This cannot overflow because we know that
        // `self.memory_size <= self.memory_capacity <= MAX_SIZE`
        // and `memory_size <= MAX_SIZE == usize::MAX / 2`.
        self.memory_size += memory_size;
        // Similar as for `memory_size``.
        self.disk_size += disk_size;
        let mut evicted_entries = self.evict();
        self.check_invariants();

        evicted_entries.extend(removed_entry);
        evicted_entries
    }

    /// Removes and returns the value corresponding to the key from the cache or
    /// `None` if it does not exist.
    pub fn pop(&mut self, key: &K) -> Option<V> {
        match self.cache.pop_entry(key) {
            Some((key, value)) => {
                self.pop_inner(&key, &value);
                self.check_invariants();
                Some(value)
            }
            _ => None,
        }
    }

    /// Remove the least recently used entry from the cache.
    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        match self.cache.pop_lru() {
            Some((key, value)) => {
                self.pop_inner(&key, &value);
                self.check_invariants();
                Some((key, value))
            }
            _ => None,
        }
    }

    /// Clears the cache by removing all items.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.memory_size = 0;
        self.disk_size = 0;
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
        while self.memory_size > self.memory_capacity || self.disk_size > self.disk_capacity {
            match self.cache.pop_lru() {
                Some((key, value)) => {
                    self.pop_inner(&key, &value);
                    ret.push((key, value));
                }
                None => break,
            }
        }
        self.check_invariants();
        ret
    }

    fn pop_inner(&mut self, key: &K, value: &V) {
        let memory_size = key.deterministic_heap_bytes() + value.deterministic_heap_bytes();
        debug_assert!(self.memory_size >= memory_size);
        // This cannot underflow because we know that `self.memory_size` is
        // the sum of memory sizes of all items in the cache.
        self.memory_size = self.memory_size.saturating_sub(memory_size);

        let disk_size = key.disk_bytes() + value.disk_bytes();
        debug_assert!(self.disk_size >= disk_size);
        // This cannot underflow because we know that `self.disk_size` is
        // the sum of disk sizes of all items in the cache.
        self.disk_size = self.disk_size.saturating_sub(disk_size);
    }

    fn check_invariants(&self) {
        // Iterating over random memory locations is expensive and slows down some tests,
        // so the debug assert is limited to 1k cache entries.
        #[cfg(debug_assertions)]
        if self.len() < 1_000 {
            debug_assert_eq!(
                self.memory_size,
                self.cache
                    .iter()
                    .map(|(key, value)| key.deterministic_heap_bytes()
                        + value.deterministic_heap_bytes())
                    .sum::<usize>()
            );
            debug_assert_eq!(
                self.disk_size,
                self.cache
                    .iter()
                    .map(|(key, value)| key.disk_bytes() + value.disk_bytes())
                    .sum::<usize>()
            );
        }
        debug_assert!(self.memory_size <= self.memory_capacity);
        debug_assert!(self.disk_size <= self.disk_capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Eq, PartialEq, Hash, Debug)]
    struct ValueSize(u32, usize);

    impl DeterministicHeapBytes for ValueSize {
        fn deterministic_heap_bytes(&self) -> usize {
            self.1
        }
    }

    impl DiskBytes for ValueSize {}

    #[derive(Clone, Eq, PartialEq, Hash, Debug)]
    struct MemoryDiskValue(u32, usize, usize);

    impl DeterministicHeapBytes for MemoryDiskValue {
        fn deterministic_heap_bytes(&self) -> usize {
            self.1
        }
    }

    impl DiskBytes for MemoryDiskValue {
        fn disk_bytes(&self) -> usize {
            self.2
        }
    }

    #[derive(Eq, PartialEq, Hash, Debug)]
    struct Key(u32);

    impl DeterministicHeapBytes for Key {
        fn deterministic_heap_bytes(&self) -> usize {
            0
        }
    }

    impl DiskBytes for Key {}

    #[test]
    fn lru_cache_single_entry() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10), NumBytes::new(0));

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
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10), NumBytes::new(0));

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
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10), NumBytes::new(0));

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
        let mut lru = LruCache::<ValueSize, ValueSize>::new(NumBytes::new(10), NumBytes::new(0));

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
        let mut lru = LruCache::<ValueSize, ValueSize>::new(NumBytes::new(10), NumBytes::new(0));

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
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10), NumBytes::new(0));
        lru.push(Key(0), ValueSize(0, 10));
        lru.clear();
        assert!(lru.get(&Key(0)).is_none());
    }

    #[test]
    fn lru_cache_pop() {
        let mut lru = LruCache::<Key, ValueSize>::new(NumBytes::new(10), NumBytes::new(0));
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
        let mut lru = LruCache::<Key, MemoryDiskValue>::new(NumBytes::new(10), NumBytes::new(20));
        assert_eq!(0, lru.deterministic_heap_bytes());
        assert_eq!(0, lru.disk_bytes());
        assert_eq!(0, lru.len());
        assert!(lru.is_empty());
        lru.push(Key(0), MemoryDiskValue(0, 4, 10));
        assert_eq!(4, lru.deterministic_heap_bytes());
        assert_eq!(10, lru.disk_bytes());
        assert_eq!(1, lru.len());
        assert!(!lru.is_empty());
        lru.push(Key(1), MemoryDiskValue(1, 6, 2));
        assert_eq!(10, lru.deterministic_heap_bytes());
        assert_eq!(12, lru.disk_bytes());
        assert_eq!(2, lru.len());
        assert!(!lru.is_empty());
        lru.pop(&Key(0));
        assert_eq!(6, lru.deterministic_heap_bytes());
        assert_eq!(2, lru.disk_bytes());
        assert_eq!(1, lru.len());
        assert!(!lru.is_empty());
        lru.pop(&Key(1));
        assert_eq!(0, lru.deterministic_heap_bytes());
        assert_eq!(0, lru.disk_bytes());
        assert_eq!(0, lru.len());
        assert!(lru.is_empty());
    }

    #[test]
    fn lru_cache_disk_and_memory_single_entry() {
        let mut lru = LruCache::<Key, MemoryDiskValue>::new(NumBytes::new(10), NumBytes::new(20));

        assert!(lru.get(&Key(0)).is_none());

        // Can't insert a value if memory or disk is too large.
        let evicted = lru.push(Key(0), MemoryDiskValue(42, 11, 0));
        assert_eq!(lru.get(&Key(0)), None);
        assert_eq!(evicted, vec![(Key(0), MemoryDiskValue(42, 11, 0))]);

        let evicted = lru.push(Key(0), MemoryDiskValue(42, 0, 21));
        assert_eq!(lru.get(&Key(0)), None);
        assert_eq!(evicted, vec![(Key(0), MemoryDiskValue(42, 0, 21))]);

        // Can insert if both sizes fit.
        let evicted = lru.push(Key(0), MemoryDiskValue(42, 10, 20));
        assert_eq!(*lru.get(&Key(0)).unwrap(), MemoryDiskValue(42, 10, 20));
        assert_eq!(evicted, vec![]);

        // Inserting a new value removes the old one if memory or disk is
        // non-zero (since both are at capacity).
        let evicted = lru.push(Key(1), MemoryDiskValue(42, 1, 0));
        assert_eq!(*lru.get(&Key(1)).unwrap(), MemoryDiskValue(42, 1, 0));
        assert_eq!(evicted, vec![(Key(0), MemoryDiskValue(42, 10, 20))]);

        lru.clear();
        let _ = lru.push(Key(0), MemoryDiskValue(42, 10, 20));
        let evicted = lru.push(Key(1), MemoryDiskValue(42, 0, 1));
        assert_eq!(*lru.get(&Key(1)).unwrap(), MemoryDiskValue(42, 0, 1));
        assert_eq!(evicted, vec![(Key(0), MemoryDiskValue(42, 10, 20))]);
    }

    #[test]
    fn lru_cache_key_and_value_eviction_mixing_memory_and_disk() {
        let mut lru =
            LruCache::<MemoryDiskValue, MemoryDiskValue>::new(NumBytes::new(10), NumBytes::new(10));

        let evicted = lru.push(MemoryDiskValue(0, 5, 1), MemoryDiskValue(42, 5, 1));
        assert_eq!(
            *lru.get(&MemoryDiskValue(0, 5, 1)).unwrap(),
            MemoryDiskValue(42, 5, 1)
        );
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(MemoryDiskValue(1, 0, 0), MemoryDiskValue(20, 0, 0));
        assert_eq!(
            *lru.get(&MemoryDiskValue(0, 5, 1)).unwrap(),
            MemoryDiskValue(42, 5, 1)
        );
        assert_eq!(
            *lru.get(&MemoryDiskValue(1, 0, 0)).unwrap(),
            MemoryDiskValue(20, 0, 0)
        );
        assert_eq!(evicted, vec![]);

        let evicted = lru.push(MemoryDiskValue(2, 5, 1), MemoryDiskValue(10, 5, 1));
        assert!(lru.get(&MemoryDiskValue(0, 5, 1)).is_none());
        assert_eq!(
            *lru.get(&MemoryDiskValue(1, 0, 0)).unwrap(),
            MemoryDiskValue(20, 0, 0)
        );
        assert_eq!(
            *lru.get(&MemoryDiskValue(2, 5, 1)).unwrap(),
            MemoryDiskValue(10, 5, 1)
        );
        // The least recently used is the first entry.
        assert_eq!(
            evicted,
            vec![(MemoryDiskValue(0, 5, 1), MemoryDiskValue(42, 5, 1))]
        );

        let evicted = lru.push(MemoryDiskValue(3, 4, 9), MemoryDiskValue(30, 0, 1));
        assert!(lru.get(&MemoryDiskValue(1, 0, 0)).is_none());
        assert!(lru.get(&MemoryDiskValue(2, 5, 1)).is_none());
        assert_eq!(
            *lru.get(&MemoryDiskValue(3, 4, 9)).unwrap(),
            MemoryDiskValue(30, 0, 1)
        );
        // Now the second and third entries are evicted.
        assert_eq!(
            evicted,
            vec![
                (MemoryDiskValue(1, 0, 0), MemoryDiskValue(20, 0, 0)),
                (MemoryDiskValue(2, 5, 1), MemoryDiskValue(10, 5, 1))
            ]
        );
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn arb_value() -> impl Strategy<Value = MemoryDiskValue> {
            (0..100_u32, 0..50_usize, 0..50_usize).prop_map(|(a, b, c)| MemoryDiskValue(a, b, c))
        }

        #[derive(Clone, Debug)]
        enum Action {
            Push(MemoryDiskValue, MemoryDiskValue),
            PopLru,
        }

        fn arb_action() -> impl Strategy<Value = Action> {
            prop_oneof![
                9 => (arb_value(), arb_value()).prop_map(|(a, b)| Action::Push(a, b)),
                1 => Just(Action::PopLru),
            ]
        }

        proptest! {
            /// Proptest checking that the internal invariants are maintained
            /// and that the total space of inserted entries equals the total
            /// space of evicted entries plus the space of the cache itself.
            #[test]
            fn test_invariants(entries in prop::collection::vec(arb_action(), 100)) {
                let mut lru = LruCache::<MemoryDiskValue, MemoryDiskValue>::new(NumBytes::new(100), NumBytes::new(100));
                let mut total_memory = 0;
                let mut total_disk = 0;
                let mut evicted_memory = 0;
                let mut evicted_disk = 0;

                fn update(memory: &mut usize, disk: &mut usize, k: &MemoryDiskValue, v: &MemoryDiskValue) {
                    *memory += k.deterministic_heap_bytes();
                    *memory += v.deterministic_heap_bytes();
                    *disk += k.disk_bytes();
                    *disk += v.disk_bytes();
                }

                for action in entries {
                    let evicted = match action {
                        Action::Push(k,v) => {
                            update(&mut total_memory, &mut total_disk, &k, &v);
                            lru.push(k,v)
                        }
                        Action::PopLru => {
                            lru.pop_lru().map_or(vec![], |e| vec![e])
                        }
                    };
                    for (k,v) in evicted {
                        update(&mut evicted_memory, &mut evicted_disk, &k, &v);
                    }

                    assert_eq!(total_memory, evicted_memory + lru.deterministic_heap_bytes());
                    assert_eq!(total_disk, evicted_disk + lru.disk_bytes());
                }
            }
        }
    }
}
