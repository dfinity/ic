use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroUsize;
use std::time::Duration;

/// A limited-size vector where older elements are evicted first.
///
/// Elements are ordered by the provided timestamp upon insertion, followed by the order of insertion.
/// That means that element `u` is older than element `v` if and only if:
/// 1. The timestamp for the insertion of `u` is before the timestamp for the insertion of `v`.
/// 2. Or, if they both have the same timestamp for insertion, `u` was inserted before `v`.
///
/// # Examples
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedSizedVec<T> {
    expiration: Duration,
    capacity: NonZeroUsize,
    size: usize,
    store: BTreeMap<Timestamp, VecDeque<T>>,
}

impl<T> TimedSizedVec<T> {
    /// Create a new empty [`TimedSizedVec`].
    ///
    /// # Examples
    ///
    /// Create a `TimeSizedVec` containing at most 10 elements which are no older than 1 minute.
    ///
    /// ```rust
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use canhttp::multi::{TimedSizedVec, Timestamp};
    ///
    /// let mut vec = TimedSizedVec::new(Duration::from_secs(60), NonZeroUsize::new(10).unwrap());
    ///
    /// let _evicted = vec.insert_evict(Timestamp::from_nanos_since_unix_epoch(1), "a");
    /// ```
    pub fn new(expiration: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            expiration,
            capacity,
            size: 0,
            store: BTreeMap::default(),
        }
    }

    /// Insert a new element and return evicted elements.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::collections::{BTreeMap, VecDeque};
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use maplit::btreemap;
    /// use canhttp::multi::{TimedSizedVec, Timestamp};
    ///
    /// let mut vec = TimedSizedVec::new(Duration::from_secs(10), NonZeroUsize::new(3).unwrap());
    ///
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "a"), BTreeMap::default());
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "b"), BTreeMap::default());
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "bb"), BTreeMap::default());
    ///
    /// // Evict "a" because size is limited to 3 elements.
    /// assert_eq!(
    ///     vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)), "c"),
    ///     btreemap! {Timestamp::from_unix_epoch(Duration::from_secs(1)) => VecDeque::from(["a"])}
    /// );
    ///
    /// // Evict "b" and "bb" because expired.
    /// assert_eq!(
    ///     vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(13)), "m"),
    ///     btreemap! { Timestamp::from_unix_epoch(Duration::from_secs(2)) => VecDeque::from(["b", "bb"]) }
    /// );
    /// ```
    pub fn insert_evict(&mut self, now: Timestamp, value: T) -> BTreeMap<Timestamp, VecDeque<T>> {
        assert!(
            self.size <= self.capacity.get(),
            "BUG: expected at most {} elements, but got {}",
            self.capacity,
            self.size
        );
        let mut evicted = self.evict_expired(now);
        if self.size == self.capacity.get() {
            if let Some((timestamp, value)) = self.remove_oldest() {
                let values = evicted.entry(timestamp).or_default();
                values.push_front(value)
            }
        }
        assert!(
            self.size < self.capacity.get(),
            "BUG: expected at most {} elements, but got {}",
            self.capacity,
            self.size
        );
        let values = self.store.entry(now).or_default();
        values.push_back(value);
        self.size += 1;
        evicted
    }

    /// Evict expired elements.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::collections::{BTreeMap, VecDeque};
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use maplit::btreemap;
    /// use canhttp::multi::{TimedSizedVec, Timestamp};
    ///
    /// let mut vec = TimedSizedVec::new(Duration::from_secs(10), NonZeroUsize::new(3).unwrap());
    ///
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "a"), BTreeMap::default());
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "b"), BTreeMap::default());
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "bb"), BTreeMap::default());
    ///
    /// assert_eq!(vec.evict_expired(Timestamp::from_unix_epoch(Duration::from_secs(11))), BTreeMap::default());
    ///
    /// assert_eq!(
    ///     vec.evict_expired(Timestamp::from_unix_epoch(Duration::from_secs(12))),
    ///     btreemap! {Timestamp::from_unix_epoch(Duration::from_secs(1)) => VecDeque::from(["a"])}
    /// );
    ///
    /// assert_eq!(
    ///     vec.evict_expired(Timestamp::from_unix_epoch(Duration::from_secs(13))),
    ///     btreemap! {Timestamp::from_unix_epoch(Duration::from_secs(2)) => VecDeque::from(["b", "bb"])}
    /// );
    /// ```
    pub fn evict_expired(&mut self, now: Timestamp) -> BTreeMap<Timestamp, VecDeque<T>> {
        match now.checked_sub(self.expiration) {
            Some(cutoff) => {
                let mut non_expired = self.store.split_off(&cutoff);
                std::mem::swap(&mut self.store, &mut non_expired);
                let expired = non_expired;
                // adjust size
                if expired.len() < self.store.len() {
                    let num_expired_elements = expired.values().map(|values| values.len()).sum();
                    self.size = self
                        .size
                        .checked_sub(num_expired_elements)
                        .expect("BUG: unexpected number of elements");
                } else {
                    self.size = self.store.values().map(|values| values.len()).sum()
                }
                expired
            }
            None => BTreeMap::default(),
        }
    }

    fn remove_oldest(&mut self) -> Option<(Timestamp, T)> {
        self.store.first_entry().and_then(|mut entry| {
            let timestamp = *entry.key();
            if let Some(removed) = entry.get_mut().pop_front() {
                self.size = self
                    .size
                    .checked_sub(1)
                    .expect("BUG: unexpected number of elements");
                if entry.get().is_empty() {
                    let _ = entry.remove();
                }
                return Some((timestamp, removed));
            }
            None
        })
    }

    /// Iterate through the elements, older elements first.
    ///
    /// Note that this method does not evict elements and may return expired entries.
    /// Run [`self.evict_expired`] first to remove expired elements.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::collections::{BTreeMap, VecDeque};
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use canhttp::multi::{TimedSizedVec, Timestamp};
    ///
    /// let mut vec = TimedSizedVec::new(Duration::from_secs(10), NonZeroUsize::new(3).unwrap());
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "a"), BTreeMap::default());
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "b"), BTreeMap::default());
    /// assert_eq!(vec.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "bb"), BTreeMap::default());
    ///
    /// assert_eq!(
    ///     vec.iter().collect::<Vec<_>>(),
    ///     vec![
    ///         (&Timestamp::from_unix_epoch(Duration::from_secs(1)), &"a"),
    ///         (&Timestamp::from_unix_epoch(Duration::from_secs(2)), &"b"),
    ///         (&Timestamp::from_unix_epoch(Duration::from_secs(2)), &"bb"),
    ///     ]
    /// );
    /// ```
    ///
    /// [`self.evict_expired`]: Self::evict_expired
    pub fn iter(&self) -> impl Iterator<Item = (&Timestamp, &T)> {
        self.store
            .iter()
            .flat_map(|(timestamp, values)| values.iter().map(move |value| (timestamp, value)))
    }

    /// Returns the number of elements.
    ///
    /// To avoid containing expired elements, call [`Self::evict_expired`] first to remove expired elements.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns true if the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns the maximum number of elements that can be stored.
    pub fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }
}

/// Time in nanoseconds since the epoch (1970-01-01).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp(Duration);

impl Timestamp {
    /// The Unix epoch.
    pub const UNIX_EPOCH: Timestamp = Timestamp::from_nanos_since_unix_epoch(0);

    /// Create a new [`Timestamp`] from a number of nanoseconds since the Unix epoch.
    pub const fn from_nanos_since_unix_epoch(nanos: u64) -> Self {
        Timestamp::from_unix_epoch(Duration::from_nanos(nanos))
    }

    /// Create a new [`Timestamp`] from a [`Duration`] since the Unix epoch.
    pub const fn from_unix_epoch(duration: Duration) -> Self {
        Timestamp(duration)
    }

    /// Checked `Time` subtraction with a `Duration`. Computes `self - rhs`,
    /// returning [`None`] if underflow occurs.
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// use std::time::Duration;
    /// use canhttp::multi::Timestamp;
    ///
    /// assert_eq!(Timestamp::from_nanos_since_unix_epoch(3).checked_sub(Duration::from_nanos(2)), Some(Timestamp::from_nanos_since_unix_epoch(1)));
    /// assert_eq!(Timestamp::from_nanos_since_unix_epoch(2).checked_sub(Duration::from_nanos(3)), None);
    /// ```
    pub fn checked_sub(self, rhs: Duration) -> Option<Timestamp> {
        self.0.checked_sub(rhs).map(Timestamp::from_unix_epoch)
    }
}

/// A map where values are limited-size vectors with older elements evicted first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedSizedMap<K, V> {
    expiration: Duration,
    capacity: NonZeroUsize,
    store: BTreeMap<K, TimedSizedVec<V>>,
}

impl<K, V> TimedSizedMap<K, V> {
    /// Create a new empty [`TimedSizedMap`],
    /// where each key contains at most `capacity` elements which are no older than `expiration`.
    pub fn new(expiration: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            expiration,
            capacity,
            store: BTreeMap::default(),
        }
    }

    /// Insert a new element and return evicted elements for **that** key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::collections::{BTreeMap, VecDeque};
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use maplit::btreemap;
    /// use canhttp::multi::{TimedSizedMap, Timestamp};
    ///
    /// let mut map = TimedSizedMap::new(Duration::from_secs(10), NonZeroUsize::new(3).unwrap());
    ///
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "key1", "a"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "key1", "b"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "key1", "bb"), BTreeMap::default());
    ///
    /// // Evict "a" because size is limited to 3 elements.
    /// assert_eq!(
    ///     map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)),"key1", "c"),
    ///     btreemap! {Timestamp::from_unix_epoch(Duration::from_secs(1)) => VecDeque::from(["a"])}
    /// );
    ///
    /// // Evict "b" and "bb" because expired.
    /// assert_eq!(
    ///     map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(13)),"key1", "m"),
    ///     btreemap! { Timestamp::from_unix_epoch(Duration::from_secs(2)) => VecDeque::from(["b", "bb"]) }
    /// );
    ///
    /// // Other keys are not impacted.
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(26)), "key2", "z"), BTreeMap::default());
    /// ```
    pub fn insert_evict(
        &mut self,
        now: Timestamp,
        key: K,
        value: V,
    ) -> BTreeMap<Timestamp, VecDeque<V>>
    where
        K: Ord,
    {
        let values = self
            .store
            .entry(key)
            .or_insert_with(|| TimedSizedVec::new(self.expiration, self.capacity));
        values.insert_evict(now, value)
    }

    /// Sort given keys according to some ordering derived from the values.
    ///
    /// To avoid containing expired elements, call [`Self::evict_expired`] first to remove expired elements.
    ///
    /// # Examples
    ///
    /// Sort keys by descending number of non-expired values.
    /// ```rust
    /// use std::collections::{BTreeMap, VecDeque};
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use maplit::btreemap;
    /// use canhttp::multi::{TimedSizedMap, TimedSizedVec, Timestamp};
    ///
    /// let mut map = TimedSizedMap::new(Duration::from_secs(10), NonZeroUsize::new(3).unwrap());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "key1", "a"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "key1", "aa"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "key1", "b"), BTreeMap::default());
    ///
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)), "key2", "c"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)), "key2", "cc"), BTreeMap::default());
    ///
    /// let now = Timestamp::from_unix_epoch(Duration::from_secs(12)); //elements "a" and "aa" expired.
    ///
    /// assert_eq!(
    ///     map.sort_keys_by(&["key1", "key2", "key3"], |values| {
    ///         ascending_num_elements(values)
    ///     }).collect::<Vec<_>>(),
    ///     vec![&"key1", &"key2", &"key3"]
    /// );
    ///
    /// fn ascending_num_elements<V>(values: Option<&TimedSizedVec<V>>) -> impl Ord {
    ///     std::cmp::Reverse(values.map(|v| v.len()).unwrap_or_default())
    /// }
    /// ```
    pub fn sort_keys_by<'a, ExtractSortKeyFn, SortKey, Q>(
        &mut self,
        keys: &'a [Q],
        extractor: ExtractSortKeyFn,
    ) -> impl Iterator<Item = &'a Q>
    where
        K: Borrow<Q> + Ord,
        Q: Ord,
        ExtractSortKeyFn: Fn(Option<&TimedSizedVec<V>>) -> SortKey,
        SortKey: Ord,
    {
        let mut sorted_keys = Vec::with_capacity(keys.len());
        for key in keys {
            let sort_key = extractor(self.store.get(key));
            sorted_keys.push((sort_key, key));
        }
        sorted_keys.sort_by(|(left_sort_key, _left_key), (right_sort_key, _right_key)| {
            left_sort_key.cmp(right_sort_key)
        });
        sorted_keys.into_iter().map(|(_sort_key, key)| key)
    }

    /// Evict expired entries for the given keys.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::collections::{BTreeMap, VecDeque};
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use maplit::btreemap;
    /// use canhttp::multi::{TimedSizedMap, TimedSizedVec, Timestamp};
    ///
    /// let mut map = TimedSizedMap::new(Duration::from_secs(10), NonZeroUsize::new(3).unwrap());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "key1", "a"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "key1", "aa"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "key1", "b"), BTreeMap::default());
    ///
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)), "key2", "c"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)), "key2", "cc"), BTreeMap::default());
    ///
    /// let now = Timestamp::from_unix_epoch(Duration::from_secs(12)); //elements "a" and "aa" expired.
    ///
    /// let expired = map.evict_expired(&["key1", "key2", "key3"], now);
    ///
    /// assert_eq!(
    ///     expired,
    ///     btreemap! {
    ///         &"key1" => btreemap! {
    ///                 Timestamp::from_unix_epoch(Duration::from_secs(1)) => VecDeque::from(["a", "aa"])
    ///             }
    ///     }
    /// );
    ///
    /// assert_eq!(
    ///     map.iter().collect::<Vec<_>>(),
    ///     vec![
    ///         (&"key1", &Timestamp::from_unix_epoch(Duration::from_secs(2)), &"b"),
    ///         (&"key2", &Timestamp::from_unix_epoch(Duration::from_secs(3)), &"c"),
    ///         (&"key2", &Timestamp::from_unix_epoch(Duration::from_secs(3)), &"cc"),
    ///     ]
    /// );
    pub fn evict_expired<'a, Q>(
        &mut self,
        keys: &'a [Q],
        now: Timestamp,
    ) -> BTreeMap<&'a Q, BTreeMap<Timestamp, VecDeque<V>>>
    where
        K: Borrow<Q> + Ord,
        Q: Ord,
    {
        let mut visited_keys = BTreeSet::new();
        let mut expired = BTreeMap::default();
        for key in keys {
            if visited_keys.insert(key) {
                if let Some(values) = self.store.get_mut(key) {
                    let expired_values = values.evict_expired(now);
                    if !expired_values.is_empty() {
                        expired.insert(key, expired_values);
                    }
                }
            }
        }
        expired
    }

    /// Iterates over the elements in the map, sorted by keys.
    ///
    /// # Examples
    ///
    /// ```rust
    ///
    /// use std::collections::{BTreeMap, VecDeque};
    /// use std::num::NonZeroUsize;
    /// use std::time::Duration;
    /// use canhttp::multi::{TimedSizedMap, TimedSizedVec, Timestamp};
    ///
    /// let mut map = TimedSizedMap::new(Duration::from_secs(10), NonZeroUsize::new(3).unwrap());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "keyZ", "a"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(1)), "keyZ", "aa"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(2)), "keyZ", "b"), BTreeMap::default());
    ///
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)), "keyA", "c"), BTreeMap::default());
    /// assert_eq!(map.insert_evict(Timestamp::from_unix_epoch(Duration::from_secs(3)), "keyA", "cc"), BTreeMap::default());
    ///
    /// assert_eq!(
    ///     map.iter().collect::<Vec<_>>(),
    ///     vec![
    ///         (&"keyA", &Timestamp::from_unix_epoch(Duration::from_secs(3)), &"c"),
    ///         (&"keyA", &Timestamp::from_unix_epoch(Duration::from_secs(3)), &"cc"),
    ///         (&"keyZ", &Timestamp::from_unix_epoch(Duration::from_secs(1)), &"a"),
    ///         (&"keyZ", &Timestamp::from_unix_epoch(Duration::from_secs(1)), &"aa"),
    ///         (&"keyZ", &Timestamp::from_unix_epoch(Duration::from_secs(2)), &"b"),
    ///     ]
    /// );
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&K, &Timestamp, &V)> {
        self.store.iter().flat_map(|(k, values)| {
            values
                .iter()
                .map(move |(timestamp, value)| (k, timestamp, value))
        })
    }
}
