use ic_btc_interface::{Height, Utxo};
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Utxo wrapper that follows the order of ascending height.
#[derive(Ord, PartialEq, Eq, Clone, Debug)]
struct OrderedUtxo(Utxo);

impl PartialOrd for OrderedUtxo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.0.height.partial_cmp(&other.0.height) {
            Some(Ordering::Equal) => self.0.partial_cmp(&other.0),
            ord => ord,
        }
    }
}

/// Implements a Utxo set that always maintains its set of utxos within a specified height diff,
/// i.e., it guarantees the diff between the max and min heights of the utxos in the set is
/// always less than or equal to the given diff. Utxos with heights below the diff from the
/// max height of all utxos in the set will be pruned during insertion.
pub struct OrderedUtxoSet {
    set: BTreeSet<OrderedUtxo>,
    max_height_diff: u32,
}

impl OrderedUtxoSet {
    pub fn new(max_height_diff: u32) -> Self {
        Self {
            set: BTreeSet::new(),
            max_height_diff,
        }
    }

    pub fn contains(&self, utxo: &Utxo) -> bool {
        self.set.contains(&OrderedUtxo(utxo.clone()))
    }

    pub fn insert(&mut self, utxo: Utxo) {
        let height = utxo.height;
        let min_height = self.set.first().map(|utxo| utxo.0.height);
        let max_height = self.set.last().map(|utxo| utxo.0.height);
        if Some(height) >= min_height {
            self.set.insert(OrderedUtxo(utxo));
            if Some(height) > max_height {
                self.purge_below_height(height.saturating_sub(self.max_height_diff))
            }
        }
    }

    fn purge_below_height(&mut self, height: Height) {
        loop {
            match self.set.first() {
                Some(utxo) if utxo.0.height < height => {
                    self.set.pop_first();
                }
                _ => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_btc_interface::{OutPoint, Txid};

    fn make_utxo(height: u32, vout: u32) -> Utxo {
        Utxo {
            outpoint: OutPoint {
                txid: Txid::from([0u8; 32]),
                vout,
            },
            value: 1_000,
            height,
        }
    }

    #[test]
    fn empty_set_does_not_contain() {
        let set = OrderedUtxoSet::new(100);
        assert!(!set.contains(&make_utxo(100, 0)));
    }

    #[test]
    fn insert_and_contains() {
        let mut set = OrderedUtxoSet::new(100);
        let utxo = make_utxo(100, 0);
        set.insert(utxo.clone());
        assert!(set.contains(&utxo));
        // Different UTXO (same height, different vout) is not present.
        assert!(!set.contains(&make_utxo(100, 1)));
    }

    #[test]
    fn rejects_utxo_below_min_height() {
        let mut set = OrderedUtxoSet::new(100);
        let first = make_utxo(200, 0);
        set.insert(first.clone());

        // UTXO with height strictly below current min is ignored.
        let below = make_utxo(199, 1);
        set.insert(below.clone());
        assert!(set.contains(&first));
        assert!(!set.contains(&below));
    }

    #[test]
    fn accepts_utxo_at_min_height() {
        let mut set = OrderedUtxoSet::new(100);
        let first = make_utxo(200, 0);
        set.insert(first.clone());

        // UTXO with height equal to current min is accepted.
        let at_min = make_utxo(200, 1);
        set.insert(at_min.clone());
        assert!(set.contains(&first));
        assert!(set.contains(&at_min));
    }

    #[test]
    fn multiple_utxos_at_same_height_all_kept() {
        let mut set = OrderedUtxoSet::new(100);
        let utxos: Vec<Utxo> = (0..5).map(|vout| make_utxo(500, vout)).collect();
        for u in &utxos {
            set.insert(u.clone());
        }
        for u in &utxos {
            assert!(set.contains(u));
        }
    }

    #[test]
    fn no_pruning_when_height_does_not_exceed_max() {
        // Inserting at height equal to current max must not trigger pruning.
        let mut set = OrderedUtxoSet::new(10);
        let low = make_utxo(100, 0);
        let high = make_utxo(110, 1);
        set.insert(low.clone());
        set.insert(high.clone());

        // Insert another UTXO at the same height as the max — no pruning expected.
        let same_as_max = make_utxo(110, 2);
        set.insert(same_as_max.clone());
        assert!(set.contains(&low));
        assert!(set.contains(&high));
        assert!(set.contains(&same_as_max));
    }

    #[test]
    fn pruning_on_new_max_height() {
        // With max_height_diff=10, inserting height 120 prunes everything below 110.
        let mut set = OrderedUtxoSet::new(10);
        let old = make_utxo(100, 0);
        let mid = make_utxo(110, 1);
        set.insert(old.clone());
        set.insert(mid.clone());

        let new_max = make_utxo(120, 2);
        set.insert(new_max.clone());

        // 100 < 120 - 10 = 110, so it's pruned.
        assert!(!set.contains(&old));
        // 110 is NOT strictly less than 110, so it's kept.
        assert!(set.contains(&mid));
        assert!(set.contains(&new_max));
    }

    #[test]
    fn pruning_boundary_inclusive() {
        // purge_below_height uses strict-less-than, so the UTXO at exactly
        // (new_max - max_height_diff) is retained.
        let mut set = OrderedUtxoSet::new(50);
        let at_boundary = make_utxo(150, 0);
        let below_boundary = make_utxo(149, 1);
        set.insert(at_boundary.clone());
        set.insert(below_boundary.clone());

        // Insert at height 200: prune below 200 - 50 = 150.
        let trigger = make_utxo(200, 2);
        set.insert(trigger.clone());

        assert!(set.contains(&at_boundary));
        assert!(!set.contains(&below_boundary));
        assert!(set.contains(&trigger));
    }

    #[test]
    fn sliding_window_prunes_old_entries() {
        let mut set = OrderedUtxoSet::new(5);
        // Insert heights 1..=10 sequentially.
        for i in 1u32..=10 {
            set.insert(make_utxo(i, i));
        }
        // After inserting height 10, prune below 10 - 5 = 5.
        // Heights 1,2,3,4 should be gone; 5..=10 should remain.
        for i in 1u32..=4 {
            assert!(
                !set.contains(&make_utxo(i, i)),
                "height {i} should be pruned"
            );
        }
        for i in 5u32..=10 {
            assert!(
                set.contains(&make_utxo(i, i)),
                "height {i} should be present"
            );
        }
    }

    #[test]
    fn saturating_sub_prevents_underflow_at_low_heights() {
        // max_height_diff larger than the inserted height must not panic and
        // must not prune the freshly inserted UTXO.
        let mut set = OrderedUtxoSet::new(1000);
        let utxo = make_utxo(5, 0);
        set.insert(utxo.clone());
        assert!(set.contains(&utxo));
    }
}
