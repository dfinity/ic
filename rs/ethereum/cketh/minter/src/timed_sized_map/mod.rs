use minicbor::{Decode, Encode};
use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroUsize;
use std::time::Duration;

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
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Entry<V> {
    pub value: V,
    pub expires_at: Timestamp,
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

    /// Reconstruct a map verbatim from its `ttl`, `capacity`, and the entries
    /// previously produced by [`Self::iter_by_expiry`].
    ///
    /// Unlike [`Self::insert_entry`], entries are admitted exactly as given: no
    /// expiry clamping, no eviction of already-expired entries, and no capacity
    /// enforcement. Preserving the [`Self::iter_by_expiry`] order reconstructs
    /// the time index bucket-for-bucket, so the result equals the map that
    /// produced the entries. Intended for event-log replay, where the snapshot
    /// is trusted; a duplicate key is a corrupt snapshot and panics.
    pub fn from_ordered_entries(
        ttl: Duration,
        capacity: NonZeroUsize,
        entries: impl IntoIterator<Item = (K, Entry<V>)>,
    ) -> Self {
        let mut map = Self::new(ttl, capacity);
        for (key, entry) in entries {
            map.by_time
                .entry(entry.expires_at)
                .or_default()
                .push_back(key.clone());
            let previous = map.entries.insert(key, entry);
            assert!(
                previous.is_none(),
                "BUG: from_ordered_entries received a duplicate key"
            );
        }
        map
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
        self.insert_entry(
            now,
            key,
            Entry {
                value,
                expires_at: self.expiry(now),
            },
        )
    }

    /// Insert a timestamped `value` under `key`.
    ///
    /// Inserting an already-expired entry is a no-op.
    /// The entry's validity is clamped to that of the one defined by the cache.
    pub fn insert_entry(
        &mut self,
        now: Timestamp,
        key: K,
        entry: Entry<V>,
    ) -> Result<Vec<(K, V)>, InsertError<K, V>> {
        if is_expired(entry.expires_at, now) {
            return Ok(vec![]);
        }
        if self.get(now, &key).is_some() {
            return Err(InsertError::AlreadyPresent {
                key,
                value: entry.value,
            });
        }
        let evicted = self.evict_expired(now);
        if self.entries.len() >= self.capacity.get() {
            return Err(InsertError::AtCapacity {
                key,
                value: entry.value,
            });
        }
        let mut entry = entry;
        entry.expires_at = entry.expires_at.min(self.expiry(now));
        self.by_time
            .entry(entry.expires_at)
            .or_default()
            .push_back(key.clone());
        self.entries.insert(key, entry);
        Ok(evicted)
    }

    /// The live value under `key`, or `None` if absent or expired as of `now`.
    pub fn get(&self, now: Timestamp, key: &K) -> Option<&V> {
        self.get_entry(now, key).map(|entry| &entry.value)
    }

    /// The live entry under `key` (value together with its expiry time), or `None` if absent or
    /// expired as of `now`.
    pub fn get_entry(&self, now: Timestamp, key: &K) -> Option<&Entry<V>> {
        let entry = self.entries.get(key)?;
        if is_expired(entry.expires_at, now) {
            None
        } else {
            Some(entry)
        }
    }

    /// Evict and return every entry that has outlived its `ttl` as of `now`.
    pub fn evict_expired(&mut self, now: Timestamp) -> Vec<(K, V)> {
        let mut evicted = Vec::new();
        while let Some(&expires_at) = self.by_time.keys().next() {
            if !is_expired(expires_at, now) {
                break;
            }
            let bucket = self
                .by_time
                .remove(&expires_at)
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

    /// Iterate all entries (live and expired-but-not-yet-evicted) in time-index
    /// order: ascending expiry, and insertion order within a shared expiry. This
    /// is the order [`Self::from_ordered_entries`] must be fed to reconstruct an
    /// identical map.
    pub fn iter_by_expiry(&self) -> impl Iterator<Item = (&K, &Entry<V>)> {
        self.by_time.values().flatten().map(|key| {
            let entry = self.entries.get(key).expect("BUG: indexed key must exist");
            (key, entry)
        })
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

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The expiry timestamp for an entry inserted at `now`, i.e. `now + ttl`.
    fn expiry(&self, now: Timestamp) -> Timestamp {
        let ttl_nanos = u64::try_from(self.ttl.as_nanos()).unwrap_or(u64::MAX);
        Timestamp::from_nanos(now.as_nanos().saturating_add(ttl_nanos))
    }
}

/// Whether an entry expiring at `expires_at` is expired as of `now`. An entry
/// remains live through its expiry instant (inclusive).
fn is_expired(expires_at: Timestamp, now: Timestamp) -> bool {
    now > expires_at
}
