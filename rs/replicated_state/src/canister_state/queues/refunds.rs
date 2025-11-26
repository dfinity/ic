use ic_types::messages::Refund;
use ic_types::{CanisterId, Cycles};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
mod tests;

/// A prioritized pool of refunds to canisters. Used for accumulating outbound
/// refunds at the subnet level, before routing into streams.
///
/// Refunds are ordered by amount (larger amounts first). Ties are broken by
/// recipient (smaller IDs first).
#[derive(Debug, Clone, Default, PartialEq, Eq, ValidateEq)]
pub struct RefundPool {
    /// Refund priority queue. Holds all refunds, ordered by amount.
    ///
    /// Canister IDs break ties, ensuring deterministic ordering.
    refunds: BTreeSet<Refund>,

    // Refund amounts, by recipient.
    #[validate_eq(Ignore)]
    amounts: BTreeMap<CanisterId, Cycles>,
}

impl RefundPool {
    pub fn new() -> Self {
        Self {
            refunds: BTreeSet::new(),
            amounts: BTreeMap::new(),
        }
    }

    /// Adds `cycles` to the amount to be refunded to `receiver`.
    pub fn add(&mut self, receiver: CanisterId, cycles: Cycles) {
        if cycles.is_zero() {
            return;
        }

        let amount = match self.amounts.entry(receiver) {
            // New receiver, insert it into `amounts`.
            Vacant(entry) => {
                entry.insert(cycles);
                cycles
            }

            // Existing receiver, remove it from `priority_queue` and  increase the amount.
            Occupied(mut entry) => {
                let amount = entry.get_mut();
                assert!(self.refunds.remove(&Refund::anonymous(receiver, *amount)));
                *amount += cycles;
                *amount
            }
        };

        // Add the updated amount to the priority queue.
        assert!(self.refunds.insert(Refund::anonymous(receiver, amount)));

        debug_assert_eq!(self.amounts.len(), self.refunds.len());
    }

    /// Retains only the refunds for which the predicate `f` returns `true`.
    pub fn retain(&mut self, mut f: impl FnMut(&Refund) -> bool) {
        self.refunds.retain(|refund| f(refund));
        self.amounts.retain(|receiver, amount| {
            self.refunds
                .contains(&Refund::anonymous(*receiver, *amount))
        });

        debug_assert_eq!(self.amounts.len(), self.refunds.len());
    }

    pub fn iter(&self) -> impl Iterator<Item = &Refund> {
        self.refunds.iter()
    }

    /// Returns the size of the pool.
    pub fn len(&self) -> usize {
        self.refunds.len()
    }

    /// Returns `true` if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.refunds.is_empty()
    }

    /// Computes the total amount of pooled cycles.
    ///
    /// Complexity: `O(n)`
    #[cfg(debug_assertions)]
    pub(crate) fn compute_total(&self) -> Cycles {
        self.refunds
            .iter()
            .fold(Cycles::zero(), |acc, r| acc + r.amount())
    }
}
