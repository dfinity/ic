use ic_btc_interface::Utxo;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Set of UTXOs sorted by value.
///
/// From outside, this should behave like a `BTreeSet<>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UtxoSet(BTreeSet<UtxoSortedByValue>);

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, utxo: Utxo) -> bool {
        self.0.insert(UtxoSortedByValue(utxo))
    }

    pub fn contains(&self, utxo: &Utxo) -> bool {
        self.0.contains(utxo)
    }

    pub fn remove(&mut self, utxo: &Utxo) -> Option<Utxo> {
        self.0.take(utxo).map(Utxo::from)
    }

    pub fn find_lower_bound(&self, value: u64) -> Option<&Utxo> {
        self.0.range(value..).next().map(|u| u.borrow())
    }

    pub fn pop_first(&mut self) -> Option<Utxo> {
        self.0.pop_first().map(Utxo::from)
    }

    pub fn last(&self) -> Option<&Utxo> {
        self.0.last().map(|u| u.borrow())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Utxo> {
        self.0.iter().map(|u| u.borrow())
    }
}

#[derive(Clone, Debug)]
struct UtxoSortedByValue(Utxo);

impl PartialEq for UtxoSortedByValue {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for UtxoSortedByValue {}

impl PartialOrd for UtxoSortedByValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UtxoSortedByValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.0.value.cmp(&other.0.value) {
            Ordering::Equal => self.0.cmp(&other.0),
            ordering => ordering,
        }
    }
}

impl Borrow<Utxo> for UtxoSortedByValue {
    fn borrow(&self) -> &Utxo {
        &self.0
    }
}

impl Borrow<u64> for UtxoSortedByValue {
    fn borrow(&self) -> &u64 {
        &self.0.value
    }
}

impl From<UtxoSortedByValue> for Utxo {
    fn from(utxo: UtxoSortedByValue) -> Self {
        utxo.0
    }
}

impl FromIterator<Utxo> for UtxoSet {
    fn from_iter<T: IntoIterator<Item = Utxo>>(utxos: T) -> Self {
        let mut set = UtxoSet::default();
        for utxo in utxos {
            set.insert(utxo);
        }
        set
    }
}
