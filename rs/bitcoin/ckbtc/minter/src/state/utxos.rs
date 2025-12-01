use ic_btc_interface::Utxo;
use std::collections::{btree_map, BTreeMap, BTreeSet};

/// Set of UTXOs sorted by value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UtxoSet {
    utxos: BTreeMap<u64, BTreeSet<Utxo>>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, utxo: Utxo) -> bool {
        self.utxos.entry(utxo.value).or_insert_with(BTreeSet::new).insert(utxo)
    }

    pub fn contains(&self, utxo: &Utxo) -> bool {
        self.utxos.get(&utxo.value).map(|utxos| utxos.contains(utxo)).unwrap_or(false)
    }

    pub fn remove(&mut self, utxo: &Utxo) -> Option<Utxo> {
        if let btree_map::Entry::Occupied(entry) = self.utxos.entry(utxo.value) {
            return UtxoSet::mutate_utxo_set(entry, |utxos| utxos.take(utxo));
        }
        None
    }

    /// Find a UTXO with the smallest value being at least `value`.
    pub fn find_lower_bound(&self, value: u64) -> Option<&Utxo> {
        self.utxos.range(value..).next().and_then(|(_value, utxos)| utxos.first())
    }

    /// Remove a UTXO with the smallest value.
    pub fn pop_first(&mut self) -> Option<Utxo> {
        if let Some(entry) = self.utxos.first_entry() {
            return UtxoSet::mutate_utxo_set(entry, |utxos| utxos.pop_first());
        }
        None
    }

    /// A UTXO with the largest value.
    pub fn last(&self) -> Option<&Utxo> {
        self.utxos.last_key_value().and_then(|(_value, utxos)| utxos.last())
    }

    pub fn len(&self) -> usize {
        self.utxos.values().map(|utxos| utxos.len()).sum()
    }

    pub fn iter(&self) -> impl Iterator<Item=&Utxo> {
        self.utxos.values().flat_map(|utxos| utxos.iter())
    }

    // Helper method to change an entry in `UtxoSet`.
    // It ensures the map entry will be removed if its values are empty.
    fn mutate_utxo_set<R, F: FnOnce(&mut BTreeSet<Utxo>) -> R>(mut entry: btree_map::OccupiedEntry<u64, BTreeSet<Utxo>>, mutator: F) -> R {
        let mut utxos = entry.get_mut();
        let result = mutator(&mut utxos);
        if entry.get().is_empty() {
            entry.remove_entry();
        }
        result
    }
}

impl FromIterator<Utxo> for UtxoSet {
    fn from_iter<T: IntoIterator<Item=Utxo>>(utxos: T) -> Self {
        let mut set = UtxoSet::default();
        for utxo in utxos {
            set.insert(utxo);
        }
        set
    }
}
