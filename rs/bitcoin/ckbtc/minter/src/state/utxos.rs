use ic_btc_interface::Utxo;
use std::cmp::Ordering;
use std::collections::BTreeSet;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct UtxoSet {
    utxos: BTreeSet<SortByKey<Utxo>>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SortByKey<T>(T);

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

impl<T, K> PartialOrd for SortByKey<T>
where
    T: PartialOrd + SecondaryKey<Key = K>,
    K: PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let primary_result = self.0.partial_cmp(&other.0);
        if Some(Ordering::Equal) == primary_result {
            return primary_result;
        }
        self.0
            .secondary_key()
            .partial_cmp(&other.0.secondary_key())
            .or(primary_result)
    }
}

impl<T, K> Ord for SortByKey<T>
where
    T: Ord + SecondaryKey<Key = K>,
    K: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let primary_result = self.0.cmp(&other.0);
        if Ordering::Equal == primary_result {
            return primary_result;
        }
        self.0.secondary_key().cmp(&other.0.secondary_key())
    }
}
