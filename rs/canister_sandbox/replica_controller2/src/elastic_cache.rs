//! Simple "elastic" LRU cache.
//!
//! Implement a simple LRU cache data structure. Clients can "get"
//! objects through the cache, and objects acquired in this way are
//! "pinned" in place: they cannot be evicted from cache for as long
//! as the pin exists. Clients can access the objects themselves through
//! this "pin" proxy.
//! The cache is "elastic" in that it implicitly expands to at least the
//! number of items pinned (in case this happens to exceed the size of
//! the cache).
//!
//! API-wise, the cache is used as a synchronized key-value store:
//!
//! let cache : Cache<KeyType, ValueType> = ...;
//! let pin = cache.get(key);
//! (*pin).do_something_on_cached_object();
//! ...
//! drop(pin); // or implicit by scoping; unpins the object
//!
//! Functionals that "create" and "destroy" requested objects are
//! provided as constructor parameters. Keys must be clonable.
use std::cmp::Eq;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::{Arc, Condvar, Mutex};

// Cache entries are organized in a hash table. Each hash bucket is
// itself a doubly-linked list of all entries hashing to the same
// bucket.
//
// All "unpinned" items are additionally maintained in an LRU list.
// "Pinned" items are taken out of LRU list such that they will be
// exempted from eviction.

// Notes on "unsafe" usage: The primary reason is that it is impossible
// to represent the circularity of data structures otherwise (except
// using "handles" into an array, and just making this nominally
// panic-unsafe).
//
// All unsafe accesses are indeed safe, by the data structure
// invariants explained here and established in text. Only safe
// operations are exposed in the public API, usage of this crate is
// therefore no safety violation.
//
// Data structures and formal invariants:
//
// Let E denote the set of pointers transitively reachable through
// the pointers stored in "buckets" (these are the "alive cache
// entries").
//
// Invariants:
// (I1) count == |E|
// (I2) for each bucket: bucket.first / bucket.last together with
//      all transitively reachable entries and their "hash_prev" /
//      "hash_next" pointer form a valid doubly linked list
// (I3) "lru_first / lru_last" and the "lru_prev" / "lru_next"
//      members of entries form a valid doubly linked list
// (I4) "transitivile reachable through lru_first" is a subset of E
// (I5) e in E => e is on the linked list corresponding to the bucket
//      that its "key" member hashes to
// (I6) e in E && e->pin_count == 0 => e is on lru list
// (I7) e in E && e->pin_count > 0 => e is not on lru list
// (I8) buckets.len() >= 1
// (I9) all pointers transitively reachable are either "null" or
//      pointers to "alive" memory locations
// (I10) for each entry: entry.pin_count equals the number of
//      PinnedCacheEntry instances whose "entry" pointer points
//      to this entry
// (I10') for each entry: entry.pin_count is greater or equal to
//      the number of PinnedCacheEntry instances whose "entry" pointer
//      points to this entry
// (I11) pin objects only point to "alive" cache entries
//
// Additional higher-level lifetime invariants:
// (L1) For every "pin" object returned from "cache" through "get",
//      lifetime of "cache" object exceeds lifetime of "pin" object.
//      This is accomplished by "pin" objects holdin an Arc reference to
//      the cache.
// (L2) Lifetime of every cached value exceeds lifetime of "pin"
//      object through which it is made accessible. This is accomplished
//      by ensuring that a value is never purged from cache while
//      there are pin objects referencing it.
//
// Each CacheEntry can logically be in one of three states:
// - constructing: the entry for the cache key has been reserved, but the
//   factory is still busily constructing the object. Clients hitting the same
//   cache entry have to wait until construction finishes. In this state the
//   "value" field of the CacheEntry is none. All data structure invariances
//   above hold for these entries.
// - alive: the value for the cache key is constructed and available for use.
//   All data structure invariances above hold for these entries.
// - evicting: these entries have been selected for eviction. They are
//   technically no longer part of the data structer and are not linked to
//   either the LRU or bucket linked list anymore. Instead, they temporarily
//   form a (singly) linked list of elements that will shortly be disposed of.
//
// See function "verify_invariants" that is also used in cfg(test) to
// perform invariant checking at runtime.
struct CacheRepr<K: Eq + Hash + Clone, V> {
    // Hash buckets of cache elements.
    buckets: Vec<CacheBucket<K, V>>,
    // List head pointers for LRU list of elements.
    lru_first: *mut CacheEntry<K, V>,
    lru_last: *mut CacheEntry<K, V>,
    // Total number of entries in cache (alive and constructing). NB
    // that this might become "cost" of cache when moving to weighted
    // cost of elements (i.e. entries have cost other than 1 each).
    count: usize,
}

struct CacheEntry<K: Eq + Hash + Clone, V> {
    // Key by which this element can be looked up.
    key: K,
    // Value stored for element. This is always populated when element
    // is "alive".
    value: Option<V>,
    // Pointers for "LRU" linked list.
    lru_prev: *mut CacheEntry<K, V>,
    lru_next: *mut CacheEntry<K, V>,
    // Pointers for "per-bucket" linked list.
    hash_prev: *mut CacheEntry<K, V>,
    hash_next: *mut CacheEntry<K, V>,
    // Number of pin objects pointing to this entry.
    pin_count: u64,
}

struct CacheBucket<K: Eq + Hash + Clone, V> {
    // Linked list pointers to all elements in this bucket.
    first: *mut CacheEntry<K, V>,
    last: *mut CacheEntry<K, V>,
}

// Implementations for low-level data structures.

impl<K: Eq + Hash + Clone, V> CacheEntry<K, V> {
    // All invariants preserved:
    // The newly created entry is not yet linked anywhere.
    pub fn new_pinned_constructing(key: K) -> Self {
        Self {
            key,
            value: None,
            lru_prev: std::ptr::null_mut::<Self>(),
            lru_next: std::ptr::null_mut::<Self>(),
            hash_prev: std::ptr::null_mut::<Self>(),
            hash_next: std::ptr::null_mut::<Self>(),
            pin_count: 1,
        }
    }
}

impl<K: Eq + Hash + Clone, V> CacheBucket<K, V> {
    // All invariants preserved - the newly created bucket is empty.
    pub fn new() -> Self {
        Self {
            first: std::ptr::null_mut::<CacheEntry<K, V>>(),
            last: std::ptr::null_mut::<CacheEntry<K, V>>(),
        }
    }

    // Inserts the given "entry" at the front of the bucket linked list.
    //
    // Pre-conditions:
    // - I2
    // - "entry" is not transitively reachable through self.first / self.last for
    //   either this or any other "CacheBucket" instance.
    // - "entry" is a valid pointer to a CacheEntry.
    // Post-conditions:
    // - I2
    // - self.first == entry
    //
    // The function is marked "unsafe" because it manipulates raw
    // pointers. Its safety is assured under the given pre-conditions.
    // The preconditions also make sure that the safety of other
    // CacheBucket instances is not affected by this function.
    //
    // See call sites on establishing pre-conditions.
    unsafe fn push_front(&mut self, entry: *mut CacheEntry<K, V>) {
        let next = self.first;

        (*entry).hash_prev = std::ptr::null_mut();
        (*entry).hash_next = next;
        if next.is_null() {
            self.last = entry;
        } else {
            (*next).hash_prev = entry;
        }
        self.first = entry;
    }

    // Removes the given "entry" from the bucket linked list.
    //
    // Pre-conditions:
    // - I2
    // - "entry" transitively reachable from self.first
    // Post-conditions:
    // - I2
    // - "entry" not transitively reachable from self.first
    //
    // The function is marked "unsafe" because it manipulates raw
    // pointers. Its safety is assured under the given pre-conditions.
    // The preconditions also make sure that the safety of other
    // CacheBucket instances is not affected by this function.
    unsafe fn unlink(&mut self, entry: *mut CacheEntry<K, V>) {
        // Unlink from predecessor.
        if (*entry).hash_prev.is_null() {
            self.first = (*entry).hash_next;
        } else {
            (*(*entry).hash_prev).hash_next = (*entry).hash_next;
        }

        // Unlink from successor.
        if (*entry).hash_next.is_null() {
            self.last = (*entry).hash_prev;
        } else {
            (*(*entry).hash_next).hash_prev = (*entry).hash_prev;
        }
    }
}

impl<K: Eq + Hash + Clone, V> CacheRepr<K, V> {
    // Instantiate a new cache internal representation with the
    // given number of buckets. Number of buckets will implicitly
    // be made >= 1.
    fn new(bucket_count: usize) -> Self {
        let num_buckets = bucket_count.max(1);
        let mut buckets = Vec::with_capacity(num_buckets);
        for _ in 0..num_buckets {
            buckets.push(CacheBucket::new());
        }
        Self {
            buckets,
            lru_first: std::ptr::null_mut(),
            lru_last: std::ptr::null_mut(),
            count: 0,
        }
    }

    // Removes given "entry" from the LRU linked list.
    //
    // Pre-conditions:
    // - I3
    // - "entry" transitively reachable from self.first
    // Post-conditions:
    // - I3
    // - "entry" not transitively reachable from self.first
    //
    // The function is marked "unsafe" because it manipulates raw
    // pointers. Its safety is assured under the given pre-conditions.
    // The preconditions also make sure that the safety of other
    // CacheBucket instances is not affected by this function.
    unsafe fn lru_unlink(&mut self, entry: *mut CacheEntry<K, V>) {
        let prev = (*entry).lru_prev;
        let next = (*entry).lru_next;
        if prev.is_null() {
            self.lru_first = next;
        } else {
            (*prev).lru_next = next;
        }
        if next.is_null() {
            self.lru_last = prev;
        } else {
            (*next).lru_prev = prev;
        }
    }

    // Inserts the given "entry" at the front of the LRU linked list.
    //
    // Pre-conditions:
    // - I3
    // - "entry" is not transitively reachable through self.lru_first or any other
    //   CacheRepr instance
    // - "entry" is a valid pointer to a CacheEntry.
    // Post-conditions:
    // - I3
    // - self.lru_first == entry
    //
    // The function is marked "unsafe" because it manipulates raw
    // pointers. Its safety is assured under the given pre-conditions.
    // The preconditions also make sure that the safety of other
    // CacheBucket instances is not affected by this function.
    //
    // See call sites on establishing pre-conditions.
    unsafe fn lru_push_front(&mut self, entry: *mut CacheEntry<K, V>) {
        let next = self.lru_first;
        (*entry).lru_prev = std::ptr::null_mut();
        (*entry).lru_next = next;
        if next.is_null() {
            self.lru_last = entry;
        } else {
            (*next).lru_prev = entry;
        }
        self.lru_first = entry;
    }

    // Determines correct bucket for given key. Returns the mutable
    // bucket such that an entry can be linked to it, or an entry
    // can be looked up.
    fn bucket(&mut self, key: &K) -> &mut CacheBucket<K, V> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.buckets.len();
        &mut self.buckets[index]
    }

    // Internal function for testing purposes only: Verify that all
    // data structure invariants hold. (To the extent that we can
    // check -- we cannot check the number of external objects in
    // existence, to validate pin count).
    #[cfg(test)]
    unsafe fn verify_invariants(&self) {
        let mut total = 0_usize;

        // Mutable key type needs to be allowed simply because the
        // pointer type is defined to be that way.
        #[allow(clippy::mutable_key_type)]
        let mut unpinned = std::collections::HashSet::<*mut CacheEntry<K, V>>::new();

        // Validate integrity of hash
        for index in 0..self.buckets.len() {
            let bucket = &self.buckets[index];
            let mut entry = bucket.first;
            loop {
                // Validate linked list integrity: entry->next->prev == entry.
                // Also covers the special cases at beginning and end of list.
                let next = if entry.is_null() {
                    bucket.first
                } else {
                    (*entry).hash_next
                };
                let next_prev = if next.is_null() {
                    bucket.last
                } else {
                    (*next).hash_prev
                };
                assert_eq!(entry, next_prev);

                if entry.is_null() {
                    break;
                }

                // Compute counts for other validations.
                total += 1;
                if (*entry).pin_count == 0 {
                    unpinned.insert(entry);
                }

                // Validate that entry is in correct hash bucket.
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                (*entry).key.hash(&mut hasher);
                assert_eq!(index, (hasher.finish() as usize) % self.buckets.len());

                entry = next;
            }
        }

        assert_eq!(total, self.count);

        // Validate integrity of LRU chain.
        // All unpinned (and only unpinned) entries must be on LRU
        // chain. Contents of LRU chain are a subset of hash.
        let mut entry = self.lru_first;
        loop {
            // Linked list structure, as above.
            let next = if entry.is_null() {
                self.lru_first
            } else {
                (*entry).lru_next
            };
            let next_prev = if next.is_null() {
                self.lru_last
            } else {
                (*next).lru_prev
            };
            assert_eq!(entry, next_prev);

            if entry.is_null() {
                break;
            }

            // Each entry on LRU list must be in the unpinned set. Each
            // entry must be there once. No other entry must be in the
            // unpinned set.
            assert!(unpinned.contains(&entry));
            unpinned.remove(&entry);

            entry = next;
        }

        assert!(unpinned.is_empty());
    }
}

// These are safe to be shared across threads because all access to
// them is linearized by the "mutex" in the cache data structure
// below. This annotation is necessary because the compiler cannot
// automatically infer thread-safety of raw pointer dereferences.
unsafe impl<K: Eq + Hash + Clone, V> Send for CacheEntry<K, V> {}
unsafe impl<K: Eq + Hash + Clone, V> Send for CacheBucket<K, V> {}
unsafe impl<K: Eq + Hash + Clone, V> Send for CacheRepr<K, V> {}

/// Accessor to a pinned cache entry
///
/// An entry that has been requested from cache, and that can be
/// freely accessed by caller. While this "pin" object exists, the
/// entry is locked in cache and cannot be evicted.
pub struct PinnedCacheEntry<K: Eq + Hash + Clone, V> {
    entry: *mut CacheEntry<K, V>,
    cache: Arc<Cache<K, V>>,
}
// Invariant: entry pointer is never null. This invariant is established
// in the single place where a PinnedCacheEntry is instantiated.

impl<K: Eq + Hash + Clone, V> Deref for PinnedCacheEntry<K, V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        // This is safe by class invariant and does not affect any
        // data structure invariants.
        unsafe { (*self.entry).value.as_ref().unwrap() }
    }
}

impl<K: Eq + Hash + Clone, V> Clone for PinnedCacheEntry<K, V> {
    fn clone(&self) -> Self {
        // This is safe by class invariant and maintains all
        // invariants.
        unsafe { self.cache.internal_addref(self.entry) }
    }
}

impl<K: Eq + Hash + Clone, V> Drop for PinnedCacheEntry<K, V> {
    fn drop(&mut self) {
        // This is safe by class invariant and maintains all
        // invariants.
        unsafe {
            self.cache.internal_put(self.entry);
        }
    }
}

/// Simple elastic LRU cache.
///
/// The cache stores elements of type "V", keyed by keys of type "K".
/// A deleter function is registered with the cache on instantiation.
///
/// There is a single "get" method that obtains the element associated
/// with the given key. It returns a "pin" object that ensures the
/// cache entry remains in place for the lifetime of the pin.
pub struct Cache<K: Eq + Hash + Clone, V> {
    // Internal synchronized data structure.
    repr: Mutex<CacheRepr<K, V>>,
    // Condition var that is used to coordinate construction of an entry.
    alive_cond: Condvar,
    // Maximum size of the cache.
    limit: usize,
    // Deleter functions to manage values held in cache.
    // It is called when a value is evicted from cache due to
    // size constraints. For any given key it is called exactly once.
    deleter: Box<dyn Fn(&K, V) + Send + Sync + 'static>,
}

impl<K: Eq + Hash + Clone, V> Cache<K, V> {
    /// Create new cache. When objects are deleted, they are
    /// passed to the given deleter function. The factory function
    /// to create objects is passed in to the "get" method (to support
    /// the use case when specific data is optionally required on
    /// construction), user must ensure that factory + deleter
    /// cooperate semantically.
    pub fn new<D>(deleter: D, limit: usize) -> Arc<Self>
    where
        D: Fn(&K, V) + Send + Sync + 'static,
    {
        Arc::new(Self {
            repr: Mutex::new(CacheRepr::new(limit)),
            alive_cond: Condvar::new(),
            limit,
            deleter: Box::new(deleter),
        })
    }

    // Looks up the cache entry correspending to the given key (creating
    // it if necessary). Returns an entry with pin_count increased by one.
    //
    // Pre-conditions:
    // - all invariants
    //
    // Post-conditions:
    // - all invariants except for I10
    // - entry.pin_count is one more than the number of "PinnedCacheEntry" instances
    //   pointing to it.
    // - returned entry is "alive"
    //
    // The function is marked unsafe due to manipulating raw pointers
    // and internally calling other unsafe functions. All operations
    // are unconditionally safe, dependent on integrity on data
    // structures.
    unsafe fn internal_get<F>(&self, key: &K, factory: F) -> *mut CacheEntry<K, V>
    where
        F: FnOnce(&K) -> V,
    {
        let (entry, need_construct, evict_list) = {
            let mut repr = self.repr.lock().unwrap();
            let bucket = &mut repr.bucket(key);

            // First, try to find an existing entry in the hash table.
            let mut entry = bucket.first;
            let (entry, need_construct, evict_list) = loop {
                if entry.is_null() {
                    // We could not find the entry in the cache. Reserve
                    // an entry that does not hold a value yet. Note that
                    // we still need to create the object, but we want to
                    // do that outside of the lock.
                    entry = Box::into_raw(Box::new(CacheEntry::<K, V>::new_pinned_constructing(
                        key.clone(),
                    )));
                    // temporarily violates (I1) ...
                    bucket.push_front(entry);
                    // ... restores (I1) again
                    repr.count += 1;

                    // We have expanded size of the cache with addition of new
                    // entry. Evict something else as necessary to compensate.
                    //
                    // All invariants except for (I10) hold at this point.
                    break (entry, true, self.evict(&mut repr, self.limit));
                } else if (*entry).key == *key {
                    if (*entry).pin_count == 0 {
                        // Preconditions for lru_unlink are satisfied:
                        // - due to (I6), the entry must be on LRU list
                        // - due to (I9), the entry must be alive
                        //
                        // calling this temporarily violates (I6)...
                        repr.lru_unlink(entry);
                    }
                    // ... and this restores (I6) again by correcting
                    // the pin count, but temporarily violates (I10)
                    (*entry).pin_count += 1;

                    // The entry might not be alive yet (might still be
                    // under construction). Wait until that condition
                    // is met.
                    while (*entry).value.is_none() {
                        repr = self.alive_cond.wait(repr).unwrap();
                    }
                    break (entry, false, std::ptr::null_mut());
                } else {
                    entry = (*entry).hash_next;
                }
            };

            #[cfg(test)]
            repr.verify_invariants();

            (entry, need_construct, evict_list)
        };

        self.dispose(evict_list);

        if need_construct {
            let value = Some(factory(key));
            let guard = self.repr.lock().unwrap();
            (*entry).value = value;
            self.alive_cond.notify_all();
            drop(guard);
        }

        entry
    }

    // Returns an entry to the cache: This is called when a "pin"
    // instance for this element is destroyed.
    //
    // Pre-conditions:
    // - all invariants except for (I10)
    // - entry.pin_count is one more than the number of "PinnedCacheEntry" instances
    //   pointing to it (the calling object about to be destroyed excluded from the
    //   count)
    // Post-conditions:
    // - all invariants
    //
    // This adjusts the pin count and takes further action (may lead
    // to evicting the item from cache).
    unsafe fn internal_put(&self, entry: *mut CacheEntry<K, V>) {
        // Need to allow let and return: in cfg(test) this is not
        // "really" let-and-return but there is a check in between.
        // The check also needs to be precisely in this place to be
        // of use.
        #[allow(clippy::let_and_return)]
        let evict_list = {
            let mut repr = self.repr.lock().unwrap();
            // temporarily violates (I6), restores (I10)
            (*entry).pin_count -= 1;
            let evict_list = if (*entry).pin_count == 0 {
                // restores (I6)
                repr.lru_push_front(entry);
                // all invariants satisfied now, all preconditions for
                // evict satisfied
                self.evict(&mut repr, self.limit)
            } else {
                std::ptr::null_mut()
            };

            #[cfg(test)]
            repr.verify_invariants();

            evict_list
        };

        self.dispose(evict_list);
    }

    // Creates an additional reference to this item. This is called on
    // "cloning" a pin object.
    //
    // Pre-conditions:
    // - all invariants
    // Post-conditions:
    // - all invariants except for (I10)
    // - entry.pin_count is one more than the number of "PinnedCacheEntry" instances
    //   pointing to it.
    unsafe fn internal_addref(
        self: &Arc<Self>,
        entry: *mut CacheEntry<K, V>,
    ) -> PinnedCacheEntry<K, V> {
        let mut repr = self.repr.lock().unwrap();
        (*entry).pin_count += 1;
        if (*entry).pin_count == 1 {
            // Note that this check is gratuituous -- there is no
            // code path where it is possible that pin_count == 1 is
            // at this point. However, this forces repr to be used
            // which is as essential requirement for lock.
            repr.lru_unlink(entry);
        }

        #[cfg(test)]
        repr.verify_invariants();

        PinnedCacheEntry {
            entry,
            cache: Arc::clone(self),
        }
    }

    // Checks the number of entries held in the cache against the
    // configured limit to the cache size. If there are evictable
    // entries beyond the size, they are evicted. This function
    // unlinks the entries from the data structure and returns a
    // (singly) linked list of items evicted. Actual deletion of the
    // affected values is performed in a different function such that
    // this does not hold the cache lock unnecessarily. See "dispose"
    // function below.
    //
    // Pre-conditions:
    // - all invariants except (I10) -- (I10') still must hold
    // Post-conditions:
    // - same as preconditions
    unsafe fn evict(&self, repr: &mut CacheRepr<K, V>, limit: usize) -> *mut CacheEntry<K, V> {
        let mut evict_list = std::ptr::null_mut::<CacheEntry<K, V>>();
        while !repr.lru_last.is_null() && repr.count > limit {
            let entry = repr.lru_last;
            // Assert: entry.pin_count == 0 (by invariant (I6) && (I4))
            // Temporarily violates (I1)
            repr.bucket(&(*entry).key).unlink(entry);
            // (I1) restored
            repr.count -= 1;
            repr.lru_unlink(entry);
            // Move data out of memory location for deleter to deal
            // with it.

            (*entry).lru_next = evict_list;
            evict_list = entry;
        }

        #[cfg(test)]
        repr.verify_invariants();

        evict_list
    }

    // Disposes of the given entries: These are cache entries that
    // have been chosen for eviction (see "evict" function above) and
    // are no longer linked to the data structure anymore. Their
    // contents need to be handed over to the deleter.
    unsafe fn dispose(&self, evict_list: *mut CacheEntry<K, V>) {
        let mut evict_list = evict_list;
        while !evict_list.is_null() {
            let entry = evict_list;
            evict_list = (*entry).lru_next;

            (self.deleter)(&(*entry).key, (*entry).value.take().unwrap());
            drop(Box::from_raw(entry));
        }
    }

    /// Looks up an element in the cache. If and only if the element does
    /// not exist yet, the given factory function will be called to create
    /// it.
    ///
    /// Returns a "pin" handle to the requested element.
    /// The pin handle can simply be dereferenced in order to obtain
    /// access to the data.
    ///
    /// The element will not be evicted from cache while pinned.
    pub fn get<F>(self: &Arc<Self>, key: &K, factory: F) -> PinnedCacheEntry<K, V>
    where
        F: FnOnce(&K) -> V,
    {
        let entry = unsafe { self.internal_get(key, factory) };
        PinnedCacheEntry {
            entry,
            cache: Arc::clone(self),
        }
    }

    /// Obtain current occupancy of the cache (=number of elements
    /// cached).
    pub fn len(&self) -> usize {
        self.repr.lock().unwrap().count
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Eq + Hash + Clone, V> Drop for Cache<K, V> {
    fn drop(&mut self) {
        let mut repr = self.repr.lock().unwrap();
        unsafe {
            self.dispose(self.evict(&mut repr, 0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestCache = Cache<String, String>;

    use std::collections::HashSet;

    // Verify that cache entries have correct lifecycle, can be pinned,
    // and are ultimately all disposed of correctly.
    #[test]
    fn entry_lifecycle() {
        let created = Arc::new(Mutex::new(0_u64));
        let deleted = Arc::new(Mutex::new(HashSet::<String>::new()));
        let copy_of_created = Arc::clone(&created);
        let copy_of_deleted = Arc::clone(&deleted);
        let factory = move |key: &String| {
            (*copy_of_created.lock().unwrap()) += 1;
            key.clone()
        };
        let cache = TestCache::new(
            move |key, _| {
                copy_of_deleted.lock().unwrap().insert(key.to_string());
            },
            2,
        );

        // Request 3 entries from cache of size two.
        let foo_pin = cache.get(&"foo".to_string(), factory.clone());
        let bar_pin = cache.get(&"bar".to_string(), factory.clone());
        let baz_pin = cache.get(&"baz".to_string(), factory.clone());

        // All 3 entries are alive and accessible.
        assert_eq!("foo", *foo_pin);
        assert_eq!("bar", *bar_pin);
        assert_eq!("baz", *baz_pin);

        // Nothing is evicted, and cache expands beyond nominmal
        // capacity.
        assert!(deleted.lock().unwrap().is_empty());
        assert!(cache.len() == 3);
        assert_eq!(3, *created.lock().unwrap());

        // Unpinning one entry will immediately delete it to bring cache
        // within size limits.
        drop(baz_pin);
        assert_eq!(1, deleted.lock().unwrap().len());
        assert!(deleted.lock().unwrap().contains(&"baz".to_string()));

        // Dropping the rest does nothing -- they will be held in cache.
        drop(foo_pin);
        drop(bar_pin);
        assert!(deleted.lock().unwrap().len() == 1);

        // Accessing one entry again will reuse it without creating it
        // again.
        let foo_pin = cache.get(&"foo".to_string(), factory.clone());
        assert_eq!(3, *created.lock().unwrap());
        drop(foo_pin);

        // Creating another entry will evict oldest.
        let bla = cache.get(&"bla".to_string(), factory.clone());
        assert_eq!(4, *created.lock().unwrap());
        assert_eq!(2, deleted.lock().unwrap().len());
        assert!(deleted.lock().unwrap().contains(&"baz".to_string()));
        assert!(deleted.lock().unwrap().contains(&"bar".to_string()));
        drop(bla);

        // Dropping cache will delete remainder.
        drop(cache);
        assert!(deleted.lock().unwrap().len() == 4);
    }

    // Exercise all possible LRU list orderings. This ensures that
    // the invariant checker sees "unlink" operation on LRU list
    // in every location (front, middle, back).
    #[test]
    fn lru_list_integrity() {
        let factory = |key: &String| key.clone();
        let cache = TestCache::new(|_, _| {}, 3);

        let foo_pin = cache.get(&"foo".to_string(), factory);
        let bar_pin = cache.get(&"bar".to_string(), factory);
        let baz_pin = cache.get(&"baz".to_string(), factory);

        drop(foo_pin);
        drop(bar_pin);
        drop(baz_pin);

        // Order on LRU list now: baz, bar, foo

        // Take first element in LRU. Then put it back again.
        let baz_pin = cache.get(&"baz".to_string(), factory);
        drop(baz_pin);

        // Order on LRU list now: baz, bar, foo

        // Take middle element in LRU. Then put it back again.
        let bar_pin = cache.get(&"bar".to_string(), factory);
        drop(bar_pin);

        // Order on LRU list now: bar, baz, foo

        // Take last element in LRU. Then put it back again.
        let foo_pin = cache.get(&"foo".to_string(), factory);
        drop(foo_pin);
    }

    // Helper class to verify concurrency of factory for cache below.
    // See test description for explanation of what it accomplishes.
    struct FactoryGuard {
        requested: Mutex<HashSet<String>>,
        allowed: Mutex<HashSet<String>>,
        proceed: Condvar,
    }

    impl FactoryGuard {
        fn new() -> Self {
            Self {
                requested: Mutex::new(HashSet::new()),
                allowed: Mutex::new(HashSet::new()),
                proceed: Condvar::new(),
            }
        }

        // Try to proceed constructing the given key. Will block unless
        // key is in "allowed" set.
        fn start_construction(&self, key: &str) {
            self.requested.lock().unwrap().insert(key.to_string());

            let mut allowed = self.allowed.lock().unwrap();
            while !allowed.contains(key) {
                allowed = self.proceed.wait(allowed).unwrap();
            }
        }

        // Allow construction of given key to succeed.
        fn allow_construction(&self, key: String) {
            let mut allowed = self.allowed.lock().unwrap();
            allowed.insert(key);
            self.proceed.notify_all();
        }
    }

    // Verify that values can be acquired from cache concurrently:
    // - when two threads are getting the same key concurrently, one will construct
    //   the entry while the other waits. Ultimately, both will acquire the key.
    // - another thread getting an unrelated item from cache is not blocked while
    //   construction of one item is in progress.
    #[test]
    fn concurrency() {
        let factory_guard = Arc::new(FactoryGuard::new());
        let created = Arc::new(Mutex::new(0_u64));
        let deleted = Arc::new(Mutex::new(HashSet::<String>::new()));
        let copy_of_deleted = Arc::clone(&deleted);
        let cache = TestCache::new(
            move |key, _| {
                copy_of_deleted.lock().unwrap().insert(key.to_string());
            },
            2,
        );

        // Spawn a thread that tries constructing the key "foo".
        // It will block because the "factory_guard" object does not
        // have "foo" in it allowed set yet.
        let copy_of_cache = Arc::clone(&cache);
        let copy_of_factory_guard = Arc::clone(&factory_guard);
        let copy_of_created = Arc::clone(&created);
        let t1 = std::thread::spawn(move || {
            let factory = move |key: &String| {
                (*copy_of_created.lock().unwrap()) += 1;
                copy_of_factory_guard.start_construction(key);
                key.clone()
            };
            let pin = copy_of_cache.get(&"foo".to_string(), factory);
            assert_eq!("foo", *pin);
        });

        // Spawn *another* thread that tries constructing the key "foo".
        // Will be stuck same as first thread, but crucially the object
        // will only be created once (verified later).
        let copy_of_cache = Arc::clone(&cache);
        let copy_of_factory_guard = Arc::clone(&factory_guard);
        let copy_of_created = Arc::clone(&created);
        let t2 = std::thread::spawn(move || {
            let factory = move |key: &String| {
                (*copy_of_created.lock().unwrap()) += 1;
                copy_of_factory_guard.start_construction(key);
                key.clone()
            };
            let pin = copy_of_cache.get(&"foo".to_string(), factory);
            assert_eq!("foo", *pin);
        });

        // While the cache is in state of "constructing foo", it still
        // needs to be able to service other requests. Instruct factory
        // that it can construct "bar" now without blocking.
        factory_guard.allow_construction("bar".to_string());
        let copy_of_factory_guard = Arc::clone(&factory_guard);
        let copy_of_created = Arc::clone(&created);
        let factory = move |key: &String| {
            (*copy_of_created.lock().unwrap()) += 1;
            copy_of_factory_guard.start_construction(key);
            key.clone()
        };
        let pin = cache.get(&"bar".to_string(), factory.clone());
        assert_eq!("bar", *pin);
        drop(pin);

        // Let construction of "foo" proceed now.
        factory_guard.allow_construction("foo".to_string());

        // Test threads can finish now.
        assert!(t1.join().is_ok());
        assert!(t2.join().is_ok());

        // There are two objects created: "foo" and "bar". In
        // particular, "foo" was created only once despite two threads
        // requesting it concurrently.
        assert_eq!(2, *created.lock().unwrap());
    }
}
