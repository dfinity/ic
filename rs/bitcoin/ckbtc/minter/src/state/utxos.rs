use ic_btc_interface::Utxo;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Set of UTXOs sorted by value.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UtxoSet<'a> {
    utxos: BTreeSet<SortByKey<'a, Utxo>>,
}

impl<'a> UtxoSet<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, utxo: Utxo) -> bool {
        self.utxos.insert(SortByKey(Cow::Owned(utxo)))
    }

    pub fn remove(&mut self, utxo: &'a Utxo) -> bool {
        self.utxos.remove(&SortByKey(Cow::Borrowed(utxo)))
    }

    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Utxo> {
        self.utxos.iter().map(|utxo| utxo.0.as_ref())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SortByKey<'a, T: Clone>(Cow<'a, T>);

trait SecondaryKey {
    type Key;

    fn secondary_key(&self) -> &Self::Key;
}

impl SecondaryKey for Utxo {
    type Key = u64;

    fn secondary_key(&self) -> &Self::Key {
        &self.value
    }
}

impl<'a, T, K> PartialOrd for SortByKey<'a, T>
where
    T: Clone + PartialOrd + SecondaryKey<Key = K>,
    K: PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let primary_result = self.0.partial_cmp(&other.0);
        if Some(Ordering::Equal) == primary_result {
            return primary_result;
        }
        self.0
            .secondary_key()
            .partial_cmp(other.0.secondary_key())
            .or(primary_result)
    }
}

impl<'a, T, K> Ord for SortByKey<'a, T>
where
    T: Clone + Ord + SecondaryKey<Key = K>,
    K: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let primary_result = self.0.cmp(&other.0);
        if Ordering::Equal == primary_result {
            return primary_result;
        }
        self.0.secondary_key().cmp(other.0.secondary_key())
    }
}
