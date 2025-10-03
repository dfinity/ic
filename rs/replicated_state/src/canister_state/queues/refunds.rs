use ic_types::{CanisterId, Cycles};
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::{
    BTreeMap, BTreeSet,
    btree_map::Entry::{Occupied, Vacant},
};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RefundPriority(Cycles, CanisterId);

impl PartialOrd for RefundPriority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RefundPriority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.0.cmp(&other.0) {
            // Break ties by canister ID: smaller IDs have higher priority.
            std::cmp::Ordering::Equal => self.1.cmp(&other.1),

            // Reverse order for different amounts: larger amounts have higher priority.
            ord => ord.reverse(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, ValidateEq)]
pub struct RefundPool {
    // Pool contents.
    #[validate_eq(Ignore)]
    refunds: BTreeMap<CanisterId, Cycles>,

    /// Refund priority queue. Holds all refunds, ordered by amount.
    ///
    /// Canister IDs break ties, ensuring deterministic ordering.
    priority_queue: BTreeSet<RefundPriority>,
}

impl RefundPool {
    pub fn new() -> Self {
        Self {
            refunds: BTreeMap::new(),
            priority_queue: BTreeSet::new(),
        }
    }

    /// Adds `cycles` to the amount to be refunded to `receiver`.
    pub fn add(&mut self, receiver: CanisterId, cycles: Cycles) {
        if cycles.is_zero() {
            return;
        }

        let amount = match self.refunds.entry(receiver) {
            // New receiver, insert it into `refunds`.
            Vacant(entry) => {
                entry.insert(cycles);
                cycles
            }

            // Existing receiver, remove it from `priority_queue` and  increase the amount.
            Occupied(mut entry) => {
                let amount = entry.get_mut();
                assert!(
                    self.priority_queue
                        .remove(&RefundPriority(*amount, receiver))
                );
                *amount += cycles;
                *amount
            }
        };

        // Add the updated amount to the priority queue.
        assert!(self.priority_queue.insert(RefundPriority(amount, receiver)));

        debug_assert_eq!(self.refunds.len(), self.priority_queue.len());
    }

    /// Retains only the refunds for which the predicate `f` returns `true`.
    pub fn retain(&mut self, mut f: impl FnMut(&CanisterId, &Cycles) -> bool) {
        self.priority_queue
            .retain(|RefundPriority(amount, receiver)| f(receiver, amount));
        self.refunds.retain(|receiver, amount| {
            self.priority_queue
                .contains(&RefundPriority(*amount, *receiver))
        });

        debug_assert_eq!(self.refunds.len(), self.priority_queue.len());
    }

    pub fn len(&self) -> usize {
        self.refunds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refunds.is_empty()
    }
}

// struct Iter {
//     inner: std::collections::btree_set::Iter<'static, (Cycles, CanisterId)>,
// }
