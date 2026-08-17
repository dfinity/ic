//! Bounds how many queries may be suspended waiting for an HTTP outcall.
//!
//! A suspended query consumes no CPU, but pins the state snapshot it executes
//! against, blocking garbage collection for that height.

use ic_base_types::CanisterId;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Grants permission for one query to be suspended. Released on `Drop`, so
/// completion, cancellation and teardown all need no bookkeeping.
pub(super) struct SuspensionPermit {
    _permit: OwnedSemaphorePermit,
    per_canister: Arc<Mutex<HashMap<CanisterId, usize>>>,
    canister_id: CanisterId,
}

impl Drop for SuspensionPermit {
    fn drop(&mut self) {
        let mut per_canister = self.per_canister.lock().unwrap();
        match per_canister.get_mut(&self.canister_id) {
            Some(count) if *count > 1 => *count -= 1,
            // Or the map grows with every canister ever seen.
            _ => {
                per_canister.remove(&self.canister_id);
            }
        }
    }
}

pub(super) struct SuspendedQueryLimiter {
    total: Arc<Semaphore>,
    per_canister_limit: usize,
    per_canister: Arc<Mutex<HashMap<CanisterId, usize>>>,
}

impl SuspendedQueryLimiter {
    pub(super) fn new(total_limit: usize, per_canister_limit: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total_limit)),
            per_canister_limit,
            per_canister: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// `None` if either limit is reached. Never waits: a caller at the limit
    /// already pins a snapshot and has a budget running down.
    pub(super) fn try_acquire(&self, canister_id: CanisterId) -> Option<SuspensionPermit> {
        let permit = Arc::clone(&self.total).try_acquire_owned().ok()?;

        let mut per_canister = self.per_canister.lock().unwrap();
        let count = per_canister.entry(canister_id).or_insert(0);
        if *count >= self.per_canister_limit {
            // Dropping `permit` returns the slot.
            if *count == 0 {
                per_canister.remove(&canister_id);
            }
            return None;
        }
        *count += 1;
        drop(per_canister);

        Some(SuspensionPermit {
            _permit: permit,
            per_canister: Arc::clone(&self.per_canister),
            canister_id,
        })
    }

    /// The number of queries currently suspended.
    #[cfg(test)]
    fn suspended(&self) -> usize {
        self.per_canister.lock().unwrap().values().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_test_utilities_types::ids::canister_test_id;

    #[test]
    fn enforces_the_total_limit() {
        let limiter = SuspendedQueryLimiter::new(2, 10);

        let first = limiter.try_acquire(canister_test_id(1));
        let second = limiter.try_acquire(canister_test_id(2));
        assert!(first.is_some());
        assert!(second.is_some());

        assert!(
            limiter.try_acquire(canister_test_id(3)).is_none(),
            "the total limit must be enforced across canisters"
        );

        drop(first);
        assert!(limiter.try_acquire(canister_test_id(3)).is_some());
    }

    #[test]
    fn enforces_the_per_canister_limit() {
        let limiter = SuspendedQueryLimiter::new(10, 1);

        let held = limiter.try_acquire(canister_test_id(1));
        assert!(held.is_some());

        assert!(
            limiter.try_acquire(canister_test_id(1)).is_none(),
            "one canister must not exceed its own limit"
        );
        assert!(
            limiter.try_acquire(canister_test_id(2)).is_some(),
            "another canister must still be admitted"
        );

        drop(held);
        assert!(limiter.try_acquire(canister_test_id(1)).is_some());
    }

    /// Being refused by the per-canister limit must not consume a slot from the
    /// total, or a canister at its own limit would starve the whole node.
    #[test]
    fn a_per_canister_refusal_does_not_consume_a_total_slot() {
        let limiter = SuspendedQueryLimiter::new(2, 1);

        let held = limiter.try_acquire(canister_test_id(1));
        assert!(held.is_some());

        for _ in 0..10 {
            assert!(limiter.try_acquire(canister_test_id(1)).is_none());
        }

        assert!(
            limiter.try_acquire(canister_test_id(2)).is_some(),
            "refusals must not have leaked the remaining total slot"
        );
    }

    #[test]
    fn releases_slots_when_permits_are_dropped() {
        let limiter = SuspendedQueryLimiter::new(4, 4);

        let permits: Vec<_> = (0..4)
            .map(|_| limiter.try_acquire(canister_test_id(1)).unwrap())
            .collect();
        assert_eq!(limiter.suspended(), 4);

        drop(permits);

        assert_eq!(limiter.suspended(), 0);
        assert!(limiter.try_acquire(canister_test_id(1)).is_some());
    }
}
