use crate::state::{Utxos, UTXO_VALUE_MAX_SIZE_MEDIUM, UTXO_VALUE_MAX_SIZE_SMALL};
use crate::types::{Height, Storable};
use bitcoin::{OutPoint, TxOut};
use stable_structures::{btreemap, Memory, VectorMemory};

/// Methods defined for [`Utxos`] struct.
/// These are declared as a trait since [`Utxos`] is declared in a different crate.
pub trait UtxosTrait {
    /// Inserts a utxo into the map.
    fn insert(&mut self, key: OutPoint, value: (TxOut, Height));

    /// Returns the value associated with the given outpoint if it exists.
    fn get(&self, key: &OutPoint) -> Option<(TxOut, Height)>;

    /// Removes a key from the map, returning the previous value at the key if it exists.
    fn remove(&mut self, key: &OutPoint) -> Option<(TxOut, Height)>;

    /// Returns `true` if the key exists in the map, `false` otherwise.
    fn contains_key(&self, key: &OutPoint) -> bool;

    /// Gets an iterator over the entries of the map.
    /// NOTE: The entries are not guaranteed to be sorted in any particular way.
    fn iter(&self) -> Iter<VectorMemory>;
}

impl UtxosTrait for Utxos {
    fn insert(&mut self, key: OutPoint, value: (TxOut, Height)) {
        let value_encoded = value.to_bytes();

        if value_encoded.len() <= UTXO_VALUE_MAX_SIZE_SMALL as usize {
            self.small_utxos
                .insert(key.to_bytes(), value_encoded)
                .expect("Inserting small UTXO must succeed.");
        } else if value_encoded.len() <= UTXO_VALUE_MAX_SIZE_MEDIUM as usize {
            self.medium_utxos
                .insert(key.to_bytes(), value_encoded)
                .expect("Inserting medium UTXO must succeed.");
        } else {
            self.large_utxos.insert(key, value);
        }
    }

    fn get(&self, key: &OutPoint) -> Option<(TxOut, Height)> {
        let key_vec = key.to_bytes();

        if let Some(value) = self.small_utxos.get(&key_vec) {
            return Some(<(TxOut, Height)>::from_bytes(value));
        }

        if let Some(value) = self.medium_utxos.get(&key_vec) {
            return Some(<(TxOut, Height)>::from_bytes(value));
        }

        self.large_utxos.get(key).cloned()
    }

    fn remove(&mut self, key: &OutPoint) -> Option<(TxOut, Height)> {
        let key_vec = key.to_bytes();

        if let Some(value) = self.small_utxos.remove(&key_vec) {
            return Some(<(TxOut, Height)>::from_bytes(value));
        }

        if let Some(value) = self.medium_utxos.remove(&key_vec) {
            return Some(<(TxOut, Height)>::from_bytes(value));
        }

        self.large_utxos.remove(key)
    }

    fn contains_key(&self, key: &OutPoint) -> bool {
        self.small_utxos.contains_key(&key.to_bytes())
            || self.medium_utxos.contains_key(&key.to_bytes())
            || self.large_utxos.contains_key(key)
    }

    fn iter(&self) -> Iter<VectorMemory> {
        Iter::new(self)
    }
}

/// An iterator over the entries in [`Utxos`].
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Iter<'a, M: Memory> {
    small_utxos_iter: btreemap::Iter<'a, M>,
    medium_utxos_iter: btreemap::Iter<'a, M>,
    large_utxos_iter: std::collections::btree_map::Iter<'a, OutPoint, (TxOut, Height)>,
}

impl<'a> Iter<'a, VectorMemory> {
    fn new(utxos: &'a Utxos) -> Self {
        Self {
            small_utxos_iter: utxos.small_utxos.iter(),
            medium_utxos_iter: utxos.medium_utxos.iter(),
            large_utxos_iter: utxos.large_utxos.iter(),
        }
    }
}

impl<M: Memory + Clone> Iterator for Iter<'_, M> {
    type Item = (OutPoint, (TxOut, Height));

    fn next(&mut self) -> Option<Self::Item> {
        // First, iterate over the small utxos.
        if let Some((key_bytes, value_bytes)) = self.small_utxos_iter.next() {
            return Some((
                OutPoint::from_bytes(key_bytes),
                <(TxOut, Height)>::from_bytes(value_bytes),
            ));
        }

        // Second, iterate over the medium utxos.
        if let Some((key_bytes, value_bytes)) = self.medium_utxos_iter.next() {
            return Some((
                OutPoint::from_bytes(key_bytes),
                <(TxOut, Height)>::from_bytes(value_bytes),
            ));
        }

        // Finally, iterate over the large utxos.
        self.large_utxos_iter.next().map(|(k, v)| (*k, v.clone()))
    }
}
