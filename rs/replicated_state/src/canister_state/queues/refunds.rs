use ic_types::CanisterId;
use ic_types::messages::Refund;
use ic_types_cycles::Cycles;
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
#[derive(Clone, Debug, Default, ValidateEq)]
pub struct RefundPool {
    /// Refund priority queue. Holds all refunds, ordered by amount.
    ///
    /// Canister IDs break ties, ensuring deterministic ordering.
    refunds: BTreeSet<Refund>,

    // Refund amounts, by recipient.
    #[validate_eq(Ignore)]
    amounts: BTreeMap<CanisterId, Cycles>,

    /// Transient: total amount of pooled cycles.
    #[validate_eq(Ignore)]
    total: Cycles,

    /// Transient: number of refunds ever pushed into the pool and the cycles they
    /// held in total. Replica-local metrics, not part of the pool's contents (see
    /// [`Self::eq()`]): they are zero on a pool loaded from a checkpoint, i.e. they
    /// only cover the refunds pushed since replica start.
    #[validate_eq(Ignore)]
    pushed: PushedRefunds,
}

/// Cumulative count of the refunds pushed into a [`RefundPool`] and of the cycles
/// they held.
#[derive(Clone, Copy, Debug, Default)]
pub struct PushedRefunds {
    /// Number of refunds pushed into the pool.
    pub refunds: u64,

    /// Cycles held by those refunds in total.
    pub cycles: Cycles,
}

/// Compares the pooled refunds only: [`RefundPool::pushed()`] is a replica-local
/// metric, covering the refunds pushed since replica start, not part of the pool's
/// contents. `amounts` and `total` are both derived from `refunds`.
impl PartialEq for RefundPool {
    fn eq(&self, other: &Self) -> bool {
        self.refunds == other.refunds
    }
}

impl Eq for RefundPool {}

impl RefundPool {
    pub fn new() -> Self {
        Self {
            refunds: BTreeSet::new(),
            amounts: BTreeMap::new(),
            total: Cycles::zero(),
            pushed: PushedRefunds::default(),
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

        self.total += cycles;

        self.pushed.refunds += 1;
        self.pushed.cycles += cycles;

        debug_assert_eq!(self.amounts.len(), self.refunds.len());
        debug_assert_eq!(self.compute_total(), self.total);
    }

    /// Retains only the refunds for which the predicate `f` returns `true`.
    pub fn retain(&mut self, mut f: impl FnMut(&Refund) -> bool) {
        self.refunds.retain(|refund| f(refund));
        self.amounts.retain(|receiver, amount| {
            self.refunds
                .contains(&Refund::anonymous(*receiver, *amount))
        });
        // Retaining is `O(n)` anyway, so just recompute the total.
        self.total = self.compute_total();

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

    /// Returns the total amount of pooled cycles.
    pub fn total(&self) -> Cycles {
        self.total
    }

    /// Returns the number of refunds ever pushed into the pool and the cycles they
    /// held in total, since replica start.
    pub fn pushed(&self) -> PushedRefunds {
        self.pushed
    }

    /// Clears the [`Self::pushed()`] metrics. Called after loading the pool from a
    /// checkpoint, so that they only cover the refunds pushed since replica start.
    pub(crate) fn clear_pushed(&mut self) {
        self.pushed = PushedRefunds::default();
    }

    /// Computes the total amount of pooled cycles.
    ///
    /// Complexity: `O(n)`
    fn compute_total(&self) -> Cycles {
        self.refunds
            .iter()
            .fold(Cycles::zero(), |acc, r| acc + r.amount())
    }
}
