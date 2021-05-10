use ic_replicated_state::CanisterState;
use ic_types::{time::UNIX_EPOCH, CanisterId, QueryAllocation, Time};
use std::{collections::HashMap, time::Duration};

// The frequency with which the `query_allocations_used` should be purged.
const QUERY_ALLOCATIONS_PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// Tracks how much of their query allocation the canisters on this node have
/// used.
pub(crate) struct QueryAllocationsUsed {
    allocations: HashMap<CanisterId, QueryAllocation>,
    last_purge: Time,
}

impl QueryAllocationsUsed {
    /// Create a new instance to be used for user queries i.e. take allocations
    /// into account.
    pub(crate) fn new() -> Self {
        Self {
            allocations: HashMap::new(),
            last_purge: UNIX_EPOCH,
        }
    }

    /// Based on the query allocation of the canister and how much of it has
    /// already been consumed in the current interval, returns the amount of
    /// allocation that is still available for executing.
    pub(crate) fn allocation_before_execution(
        &mut self,
        canister: &CanisterState,
    ) -> QueryAllocation {
        let allocation_used = match self.allocations.get(&canister.canister_id()) {
            None => QueryAllocation::zero(),
            Some(allocation) => *allocation,
        };
        let allocation_available = QueryAllocation::default() - allocation_used;

        // Should not return the entire allocation for execution. This is
        // because if the message execution traps, then the Hypervisor deducts
        // the entire supplied allocation. This prevents the canister
        // from handling additional queries till the next purge interval. Hence,
        // set a smaller bound on how much cycles a single query can consume.
        std::cmp::min(allocation_available, QueryAllocation::max_per_message())
    }

    /// Updates the query allocation of the canister after execution.
    pub(crate) fn update_allocation_after_execution(
        &mut self,
        canister: &CanisterState,
        allocation_used: QueryAllocation,
    ) {
        let canister_id = canister.canister_id();
        let current_allocation = match self.allocations.get(&canister_id) {
            None => QueryAllocation::zero(),
            Some(allocation) => *allocation,
        };
        self.allocations
            .insert(canister_id, current_allocation + allocation_used);
    }

    /// If the last purge took place longer than
    /// `QUERY_ALLOCATIONS_PURGE_INTERVAL` before in time, purge
    /// `self.query_allocations_used`.
    pub(crate) fn purge(&mut self, current_time: Time) {
        if current_time > self.last_purge + QUERY_ALLOCATIONS_PURGE_INTERVAL {
            self.allocations.clear();
            self.last_purge = current_time;
        }
    }
}
