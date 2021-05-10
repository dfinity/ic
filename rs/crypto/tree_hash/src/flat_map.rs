//! Introduces `FlatMap` structure, a sorted map with fast lookups and appends.
//! It stores keys and values in vectors.
//!
//! NOTE: `FlatMap` isn't a general-purpose map container.

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::Serializer;
use serde::Serialize;
use std::fmt;
use std::iter::{DoubleEndedIterator, Iterator};

#[cfg(test)]
mod tests;

/// Creates a [`FlatMap`] from a list of key => value pairs.
///
/// ```
/// use ic_crypto_tree_hash::flatmap;
/// let map = flatmap!("a" => 1, "b" => 2);
///
/// assert_eq!(map.get(&"a").cloned(), Some(1));
/// assert_eq!(map.get(&"b").cloned(), Some(2));
///
/// let not_in_map = "c";
/// assert_eq!(map.get(&not_in_map).cloned(), None);
/// ```
#[macro_export]
macro_rules! flatmap {
    ( $($key:expr => $value:expr,)+ ) => (flatmap!($($key => $value),+));

    ( $($key:expr => $value:expr),* ) => {
        {
            let mut _kv = ::std::vec::Vec::new();
            $(
                _kv.push(($key, $value));
            )*
            $crate::flat_map::FlatMap::from_key_values(_kv)
        }
    };
}

/// A [`FlatMap`] is a sorted map with fast lookups and appends.
///
/// It stores keys and values in vectors.
///
/// Note that this data structure isn't a general-purpose map container.
///
/// Supported efficient operations:
///  * Construction from a vector of key-value pairs in O(N log N) time.
///  * Get a value by key in O(log N) time.
///  * Access max key in O(1) time.
///  * Insert a value with the new max key in amortized O(1) time.
///  * Iterate over keys/values in O(N) time.
///
/// Unsupported operations:
///  * Insert a value with an arbitrary key.
///
/// Remove by key is supported, but requires O(N) time worst case.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct FlatMap<K: Ord, V> {
    keys: Vec<K>,
    values: Vec<V>,
}

impl<K: Ord, V> Default for FlatMap<K, V> {
    fn default() -> Self {
        Self {
            keys: vec![],
            values: vec![],
        }
    }
}

impl<K: Ord, V> FlatMap<K, V> {
    /// Creates a new, empty map.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a new map of specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            keys: Vec::with_capacity(capacity),
            values: Vec::with_capacity(capacity),
        }
    }

    /// Constructs a map from a list of (key, value) pairs.
    ///
    /// Entries doesn't have to be sorted. Any duplicates will be removed, it's
    /// not specified which duplicate is removed.
    ///
    /// Complexity: O(log(N)×N)
    pub fn from_key_values(mut kv: Vec<(K, V)>) -> Self {
        kv.sort_by(|l, r| l.0.cmp(&r.0));
        let mut m = Self::with_capacity(kv.len());
        for (k, v) in kv {
            if Some(&k) > m.last_key() {
                let _ = m.try_append(k, v);
            }
        }
        m
    }

    /// Searches a value by key.
    ///
    /// Complexity: O(log(N))
    pub fn get(&self, key: &K) -> Option<&V> {
        self.keys
            .binary_search(key)
            .map(|idx| &self.values[idx])
            .ok()
    }

    /// Like `get`, but returns a mutable reference.
    ///
    /// Complexity: O(log(N))
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.keys
            .binary_search(key)
            .map(move |idx| &mut self.values[idx])
            .ok()
    }

    /// Removes a value by key.
    ///
    /// Complexity: O(N)
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Ok(idx) = self.keys.binary_search(key) {
            self.keys.remove(idx);
            Some(self.values.remove(idx))
        } else {
            None
        }
    }

    /// Checks if this map contains the specified key.
    ///
    /// Complexity: O(log(N))
    pub fn contains_key(&self, key: &K) -> bool {
        self.keys.binary_search(key).is_ok()
    }

    /// Returns a reference to the last key, if any.
    ///
    /// Complexity: O(1)
    pub fn last_key(&self) -> Option<&K> {
        self.keys.last()
    }

    /// Tries to extend this map by adding a new (K, V) entry.
    /// Returns an Err if the last key in this map is ≥ `key`.
    ///
    /// Complexity: O(1)
    pub fn try_append(&mut self, key: K, value: V) -> Result<(), (K, V)> {
        let ok = self
            .keys
            .last()
            .map(|last_key| *last_key < key)
            .unwrap_or(true);
        if ok {
            self.keys.push(key);
            self.values.push(value);
            Ok(())
        } else {
            Err((key, value))
        }
    }

    /// Returns an iterator over key-value pairs.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        (0..self.len()).map(move |i| (&self.keys[i], &self.values[i]))
    }

    /// Returns a sorted slice of the keys contained in this map.
    pub fn keys(&self) -> &[K] {
        &self.keys[..]
    }

    /// Returns a slice of values contained in this map.
    pub fn values(&self) -> &[V] {
        &self.values[..]
    }

    /// Returns true if this map is empty.
    /// Returns false otherwise.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Returns the number of entries in this map.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Splits the collection into two at the given key. Returns everything
    /// after the given key, including the key if present.
    pub fn split_off(&mut self, key: &K) -> Self {
        let at = self.keys.binary_search(key).unwrap_or_else(|at| at);
        Self {
            keys: self.keys.split_off(at),
            values: self.values.split_off(at),
        }
    }
}

/// An auxiliary struct for an implementation of iterators over [`FlatMap`]
pub struct IntoIter<K, V> {
    keys: std::vec::IntoIter<K>,
    values: std::vec::IntoIter<V>,
}

impl<K, V> std::iter::Iterator for IntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        let k = self.keys.next()?;
        let v = self.values.next()?;
        Some((k, v))
    }
}

impl<K, V> std::iter::DoubleEndedIterator for IntoIter<K, V> {
    fn next_back(&mut self) -> Option<(K, V)> {
        let k = self.keys.next_back()?;
        let v = self.values.next_back()?;
        Some((k, v))
    }
}

impl<K: Ord, V> std::iter::IntoIterator for FlatMap<K, V> {
    type Item = (K, V);
    type IntoIter = IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter {
            keys: self.keys.into_iter(),
            values: self.values.into_iter(),
        }
    }
}

impl<K: Serialize + Ord, V: Serialize> Serialize for FlatMap<K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.iter())
    }
}
/// An auxiliary struct for an implementation of [`Visitor`]-trait for
/// [`FlatMap`]
struct FlatMapVisitor<K: Ord, V> {
    _marker: std::marker::PhantomData<fn() -> FlatMap<K, V>>,
}

impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> Visitor<'de> for FlatMapVisitor<K, V> {
    type Value = FlatMap<K, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a flat map")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = FlatMap::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            map.try_append(key, value)
                .map_err(|_| serde::de::Error::custom("flat map keys are not sorted"))?
        }

        Ok(map)
    }
}

impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> Deserialize<'de> for FlatMap<K, V> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<FlatMap<K, V>, D::Error> {
        deserializer.deserialize_map(FlatMapVisitor {
            _marker: std::marker::PhantomData,
        })
    }
}
