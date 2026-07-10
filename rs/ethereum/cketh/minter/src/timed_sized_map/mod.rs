use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroUsize;
use std::time::Duration;

#[cfg(test)]
mod tests;

/// Nanoseconds since the Unix epoch (as returned by `ic_cdk::api::time()`).
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    fn saturating_add(self, duration: Duration) -> Self {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(nanos))
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct Entry<V> {
    value: V,
    inserted_at: Timestamp,
}

/// A map of at most `capacity` entries, each living for at most `ttl`.
///
/// On insertion, entries that have outlived their `ttl` are evicted first; if the map is still at
/// capacity with only live entries, the insertion is rejected rather than evicting a live entry.
/// Time is supplied by the caller on every operation, so the structure holds no clock and is
/// deterministic in tests.
pub struct TimedSizedMap<K, V> {
    ttl: Duration,
    capacity: NonZeroUsize,
    entries: BTreeMap<K, Entry<V>>,
    by_time: BTreeMap<Timestamp, VecDeque<K>>,
}

/// Returned by [`TimedSizedMap::insert`] when the map is already at capacity with only live
/// (unexpired) entries, so a new key cannot be admitted without evicting a live one. The rejected
/// `key` and `value` are handed back to the caller.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AtCapacity<K, V> {
    pub key: K,
    pub value: V,
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

    /// Insert `value` under `key`, first evicting any entries that have outlived their `ttl`.
    /// Re-inserting an existing key refreshes its value and lifetime; the previous value is dropped
    /// and never reported as an eviction. Returns the expired entries evicted by this call, or
    /// [`AtCapacity`] if admitting a new key would require evicting a live entry (live entries are
    /// never evicted, since a still-armed address may already have received funds).
    pub fn insert(
        &mut self,
        now: Timestamp,
        key: K,
        value: V,
    ) -> Result<Vec<(K, V)>, AtCapacity<K, V>> {
        let refreshed = self.remove(&key).is_some();
        let evicted = self.evict_expired(now);
        if !refreshed && self.entries.len() >= self.capacity.get() {
            return Err(AtCapacity { key, value });
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

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, entry)| (key, &entry.value))
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
        inserted_at.saturating_add(self.ttl) <= now
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let entry = self.entries.remove(key)?;
        self.remove_from_time_index(key, entry.inserted_at);
        Some(entry.value)
    }

    fn remove_from_time_index(&mut self, key: &K, inserted_at: Timestamp) {
        let bucket = self
            .by_time
            .get_mut(&inserted_at)
            .expect("BUG: entry timestamp missing from the time index");
        let position = bucket
            .iter()
            .position(|indexed| indexed == key)
            .expect("BUG: entry missing from its timestamp bucket");
        bucket.remove(position);
        let is_empty = bucket.is_empty();
        if is_empty {
            self.by_time.remove(&inserted_at);
        }
    }
}
