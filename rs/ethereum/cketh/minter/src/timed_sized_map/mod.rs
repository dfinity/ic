use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroUsize;
use std::time::Duration;
use minicbor::{Decode, Encode};

#[cfg(test)]
mod tests;

/// Nanoseconds since the Unix epoch (as returned by `ic_cdk::api::time()`).
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Decode, Encode)]
pub struct Timestamp(#[n(0)] u64);

impl Timestamp {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    fn checked_duration_since(self, earlier: Timestamp) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Entry<V> {
    pub value: V,
    pub inserted_at: Timestamp,
}

/// A map of at most `capacity` entries, each living for at most `ttl`.
///
/// Re-inserting a key that still has a live entry is rejected up front, leaving the map
/// untouched. Otherwise, admitting a new key first evicts entries that have outlived their `ttl`;
/// if the map is still at capacity with only live entries, the insertion is rejected rather than
/// evicting a live entry. Time is supplied by the caller on every operation, so the structure
/// holds no clock and is deterministic in tests.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct TimedSizedMap<K, V> {
    ttl: Duration,
    capacity: NonZeroUsize,
    entries: BTreeMap<K, Entry<V>>,
    by_time: BTreeMap<Timestamp, VecDeque<K>>,
}

/// Returned by [`TimedSizedMap::insert`] when a new entry cannot be admitted. The rejected `key`
/// and `value` are handed back to the caller.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum InsertError<K, V> {
    /// A live (unexpired) entry already exists under this key; refreshing it is not allowed.
    AlreadyPresent { key: K, value: V },
    /// The map is at capacity with only live entries, so no room can be freed by evicting expired.
    AtCapacity { key: K, value: V },
}

impl<K: Ord + Clone, V> TimedSizedMap<K, V> {
    pub fn new(ttl: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            ttl,
            capacity,
            entries: BTreeMap::new(),
            by_time: BTreeMap::new(),
        }
    }

    /// Insert `value` under `key`. Returns an [`InsertError`] if the key already has a live entry
    /// ([`InsertError::AlreadyPresent`] — refreshing a live entry is not allowed, so a caller cannot
    /// extend an entry's lifetime by re-inserting it; the map is left unchanged) or, after evicting
    /// any entries that have outlived their `ttl`, the map is still full of live entries
    /// ([`InsertError::AtCapacity`] — a live entry is never evicted, since a still-armed address may
    /// already have received funds). On success, returns the expired entries evicted by this call.
    pub fn insert(
        &mut self,
        now: Timestamp,
        key: K,
        value: V,
    ) -> Result<Vec<(K, V)>, InsertError<K, V>> {
        if self.get(now, &key).is_some() {
            return Err(InsertError::AlreadyPresent { key, value });
        }
        let evicted = self.evict_expired(now);
        if self.entries.len() >= self.capacity.get() {
            return Err(InsertError::AtCapacity { key, value });
        }
        self.entries.insert(
            key.clone(),
            Entry {
                value,
                inserted_at: now,
            },
        );
        self.by_time.entry(now).or_default().push_back(key);
        Ok(evicted)
    }

    /// The live value under `key`, or `None` if absent or expired as of `now`.
    pub fn get(&self, now: Timestamp, key: &K) -> Option<&V> {
        let entry = self.entries.get(key)?;
        if self.is_expired(entry.inserted_at, now) {
            None
        } else {
            Some(&entry.value)
        }
    }

    /// Evict and return every entry that has outlived its `ttl` as of `now`.
    pub fn evict_expired(&mut self, now: Timestamp) -> Vec<(K, V)> {
        let mut evicted = Vec::new();
        while let Some(&inserted_at) = self.by_time.keys().next() {
            if !self.is_expired(inserted_at, now) {
                break;
            }
            let bucket = self
                .by_time
                .remove(&inserted_at)
                .expect("BUG: bucket must exist");
            for key in bucket {
                let entry = self
                    .entries
                    .remove(&key)
                    .expect("BUG: indexed key must exist");
                evicted.push((key, entry.value));
            }
        }
        evicted
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &Entry<V>)> {
        self.entries.iter()
    }

    /// Rebuild a map from a previously captured snapshot, preserving each entry's original
    /// insertion time. This is a trusted restore of an already-valid snapshot: it performs no
    /// eviction, capacity, or refresh checks, and requires the entries to have distinct keys.
    pub fn from_entries(
        ttl: Duration,
        capacity: NonZeroUsize,
        entries: impl IntoIterator<Item = (Timestamp, K, V)>,
    ) -> Self {
        let mut map = Self::new(ttl, capacity);
        for (inserted_at, key, value) in entries {
            let previous = map
                .entries
                .insert(key.clone(), Entry { value, inserted_at });
            assert!(
                previous.is_none(),
                "BUG: from_entries received a duplicate key"
            );
            map.by_time.entry(inserted_at).or_default().push_back(key);
        }
        map
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    fn is_expired(&self, inserted_at: Timestamp, now: Timestamp) -> bool {
        now.checked_duration_since(inserted_at)
            .is_some_and(|age| age > self.ttl)
    }
}
