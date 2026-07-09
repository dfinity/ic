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
/// On insertion, entries that have outlived their `ttl` are evicted first; if the map is still
/// at capacity, the oldest remaining entries are evicted to make room. Time is supplied by the
/// caller on every operation, so the structure holds no clock and is deterministic in tests.
pub struct TimedSizedMap<K, V> {
    ttl: Duration,
    capacity: NonZeroUsize,
    entries: BTreeMap<K, Entry<V>>,
    by_time: BTreeMap<Timestamp, VecDeque<K>>,
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

    /// Insert `value` under `key`, evicting expired then oldest entries as needed to respect the
    /// `ttl` and `capacity`. Re-inserting an existing key refreshes its value and lifetime without
    /// counting against capacity. Returns the entries evicted by this call.
    pub fn insert(&mut self, now: Timestamp, key: K, value: V) -> Vec<(K, V)> {
        let mut evicted = self.evict_expired(now);
        self.remove(&key);
        while self.entries.len() >= self.capacity.get() {
            match self.evict_oldest() {
                Some(entry) => evicted.push(entry),
                None => break,
            }
        }
        self.entries.insert(
            key.clone(),
            Entry {
                value,
                inserted_at: now,
            },
        );
        self.by_time.entry(now).or_default().push_back(key);
        evicted
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
        if let Some(bucket) = self.by_time.get_mut(&inserted_at) {
            if let Some(position) = bucket.iter().position(|indexed| indexed == key) {
                bucket.remove(position);
            }
            if bucket.is_empty() {
                self.by_time.remove(&inserted_at);
            }
        }
    }

    fn evict_oldest(&mut self) -> Option<(K, V)> {
        let inserted_at = *self.by_time.keys().next()?;
        let bucket = self
            .by_time
            .get_mut(&inserted_at)
            .expect("BUG: bucket must exist");
        let key = bucket.pop_front().expect("BUG: bucket must be non-empty");
        if bucket.is_empty() {
            self.by_time.remove(&inserted_at);
        }
        let entry = self
            .entries
            .remove(&key)
            .expect("BUG: indexed key must exist");
        Some((key, entry.value))
    }
}
