#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::collections::BTreeMap;

/// A map with two keys: a primary key `Key` and an alternative key `AltKey`.
/// The stored value `V` is indexed by both keys and can be efficiently retrieved from either key.
/// Access via the primary key is done like in usual map methods: `get`, `contains`, etc.; while
/// access via the alternative key uses the suffix `_alt`: `get_alt`, `contains_alt`, etc.
/// Iterating over the map entries is done by the ordering defined on `Key`.
///
/// # Implementation Details
/// Internally, an entry `(Key, AltKey, V)` is stored as two entries in two separate maps:
/// * `(Key, AltKey)` in a BTreeMap<Key, AltKey>
/// * `(AltKey, V)` in a BTreeMap<AltKey, V>
/// Meaning that the alternative key is duplicated, but not the primary key. This allows to easily remove
/// data given the primary key since with only 2 map lookups we have the chain `Key -> AltKey -> V`.
/// In contrast, this structure is not thought to allow efficient removal by the alternative key
/// (since this would require searching first for a value in the map to retrieve the corresponding primary key).
/// If this becomes necessary, additional duplication of the primary key might be needed (e.g., one map
/// would be `BTreeMap<Key, (AltKey, V)>` while the second one would be `BTreeMap<AltKey, Key>`).
#[derive(Clone, Serialize, Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MultiKeyMap<Key, AltKey, V>
where
    Key: Ord,
    AltKey: Ord,
{
    by_alt_key: BTreeMap<AltKey, V>,
    by_key: BTreeMap<Key, AltKey>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct OccupiedError<Key, AltKey, V> {
    /// Primary key or alternative key in the map that was already occupied
    pub occupied_key: OccupiedKey<Key, AltKey>,
    /// The value which was not inserted, because the entry was already occupied.
    pub value: V,
}

#[derive(Debug, PartialEq, Clone)]
pub enum OccupiedKey<Key, AltKey> {
    /// Primary key in the map that was already occupied.
    Key(Key),
    /// Alternative key in the map that was already occupied.
    AltKey(AltKey),
}

impl<Key: Ord, AltKey: Ord, V> MultiKeyMap<Key, AltKey, V> {
    pub fn new() -> Self {
        Self {
            by_alt_key: Default::default(),
            by_key: Default::default(),
        }
    }

    pub fn try_insert(
        &mut self,
        key: Key,
        alt_key: AltKey,
        value: V,
    ) -> Result<(), OccupiedError<Key, AltKey, V>>
    where
        AltKey: Clone,
    {
        if self.by_alt_key.contains_key(&alt_key) {
            return Err(OccupiedError {
                occupied_key: OccupiedKey::AltKey(alt_key),
                value,
            });
        }
        if self.by_key.contains_key(&key) {
            return Err(OccupiedError {
                occupied_key: OccupiedKey::Key(key),
                value,
            });
        }
        assert!(self.by_alt_key.insert(alt_key.clone(), value).is_none());
        assert!(self.by_key.insert(key, alt_key).is_none());
        Ok(())
    }

    pub fn get<Q: ?Sized>(&self, key: &Q) -> Option<&V>
    where
        Key: Borrow<Q>,
        Q: Ord,
    {
        self.by_key
            .get(key)
            .and_then(|alt_key| self.by_alt_key.get(alt_key))
    }

    pub fn get_alt<Q: ?Sized>(&self, alt_key: &Q) -> Option<&V>
    where
        AltKey: Borrow<Q>,
        Q: Ord,
    {
        self.by_alt_key.get(alt_key)
    }

    pub fn contains<Q: ?Sized>(&self, key: &Q) -> bool
    where
        Key: Borrow<Q>,
        Q: Ord,
    {
        self.by_key.contains_key(key)
    }

    pub fn contains_alt<Q: ?Sized>(&self, alt_key: &Q) -> bool
    where
        AltKey: Borrow<Q>,
        Q: Ord,
    {
        self.by_alt_key.contains_key(alt_key)
    }

    /// Iterates over all stored values in the map.
    /// Elements are returned in ascending order of the primary key.
    pub fn iter(&self) -> impl Iterator<Item = (&Key, &AltKey, &V)> {
        self.by_key
            .iter()
            .map(|(key, alt_key)| (key, alt_key, &self.by_alt_key[alt_key]))
    }

    /// Remove all elements from the map that match the given predicate on the primary key.
    pub fn drain<P>(&mut self, mut predicate: P) -> Vec<(Key, AltKey, V)>
    where
        P: FnMut(&Key) -> bool,
        Key: Clone,
    {
        let mut to_remove = Vec::new();
        for (key, _alt_key) in self.by_key.iter() {
            if predicate(key) {
                to_remove.push(key.clone());
            }
        }
        let mut drained_elements = Vec::new();
        for key in to_remove {
            let (removed_key, removed_alt_key) = self
                .by_key
                .remove_entry(&key)
                .expect("BUG: missing primary key");
            let removed_value = self
                .by_alt_key
                .remove(&removed_alt_key)
                .expect("BUG: missing foreign key");
            drained_elements.push((removed_key, removed_alt_key, removed_value));
        }
        drained_elements
    }
}

impl<Key: Ord, AltKey: Ord, V> Default for MultiKeyMap<Key, AltKey, V> {
    fn default() -> Self {
        Self::new()
    }
}
