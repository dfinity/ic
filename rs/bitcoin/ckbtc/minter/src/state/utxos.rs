use ic_btc_interface::Utxo;
use std::collections::{BTreeMap, BTreeSet};

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
       self.utxos.get(&utxo.value).map(|utxos|utxos.contains(utxo)).unwrap_or(false)
    }

    pub fn remove(&mut self, utxo: &Utxo) -> Option<Utxo> {
        self.utxos.get_mut(&utxo.value).and_then(|utxos| utxos.take(utxo))
    }

    /// Find a UTXO with the smallest value being at least `value`.
    pub fn find_lower_bound(&self, value: u64) -> Option<&Utxo> {
        self.utxos.range(value..).next().and_then(|(_value, utxos)| utxos.first())
    }

    /// Remove a UTXO with the smallest value.
    pub fn pop_first(&mut self) -> Option<Utxo> {
        self.utxos.first_entry().and_then(|mut utxos| utxos.get_mut().pop_first())
    }

    /// A UTXO with the largest value.
    pub fn last(&self) -> Option<&Utxo> {
        self.utxos.last_key_value().and_then(|(_value, utxos)|utxos.last())
    }

    pub fn len(&self) -> usize {
        self.utxos.values().map(|utxos| utxos.len()).sum()
    }

    pub fn iter(&self) -> impl Iterator<Item=&Utxo> {
        self.utxos.values().flat_map(|utxos| utxos.iter())
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
