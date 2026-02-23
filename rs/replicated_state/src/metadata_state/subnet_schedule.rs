use ic_types::{AccumulatedPriority, CanisterId, ExecutionRound, LongExecutionMode};
use ic_validate_eq::ValidateEq;
use std::collections::BTreeMap;

#[cfg(test)]
pub mod tests;

/// Scheduling priority of a canister.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CanisterPriority {
    /// Keeps the current priority of this canister, accumulated during the past
    /// rounds. In the scheduler analysis documentation, this value is the entry
    /// in the vector d that corresponds to this canister.
    pub accumulated_priority: AccumulatedPriority,

    /// Keeps the current priority credit of this Canister, accumulated during long
    /// executions.
    ///
    /// During long executions, the Canister is temporarily credited with priority
    /// to slightly boost the long execution priority. Only when the long execution
    /// is done, then the `accumulated_priority` is decreased by the `priority_credit`.
    pub priority_credit: AccumulatedPriority,

    /// Long execution mode: Opportunistic (default) or Prioritized
    pub long_execution_mode: LongExecutionMode,

    /// The last full round that a canister got the chance to execute. This
    /// means that the canister was given the first pulse in the round or
    /// consumed its input queue.
    pub last_full_execution_round: ExecutionRound,
}

impl CanisterPriority {
    /// The default priority for a canister. Applied when a canister is added to the
    /// subnet schedule.
    pub const DEFAULT: CanisterPriority = CanisterPriority {
        accumulated_priority: AccumulatedPriority::new(0),
        priority_credit: AccumulatedPriority::new(0),
        long_execution_mode: LongExecutionMode::Opportunistic,
        last_full_execution_round: ExecutionRound::new(0),
    };
}

impl Default for CanisterPriority {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Scheduling priorities of all active canisters on the subnet.
#[derive(Clone, Eq, PartialEq, Debug, Default)]
pub struct SubnetSchedule {
    priorities: BTreeMap<CanisterId, CanisterPriority>,

    #[cfg(debug_assertions)]
    pub fully_executed_canisters: std::collections::BTreeSet<CanisterId>,
}

/// Two schedules are equal if they have the same canister priorities (modulo
/// default priorities).
impl ValidateEq for SubnetSchedule {
    fn validate_eq(&self, other: &Self) -> Result<(), String> {
        if self.priorities == other.priorities {
            return Ok(());
        }
        for (canister_id, priority) in self.priorities.iter() {
            if other.get(canister_id) != priority {
                return Err("SubnetSchedule::priorities".to_string());
            }
        }
        for (canister_id, priority) in other.priorities.iter() {
            if self.get(canister_id) != priority {
                return Err("SubnetSchedule::priorities".to_string());
            }
        }
        Ok(())
    }
}

impl SubnetSchedule {
    pub fn new(priorities: BTreeMap<CanisterId, CanisterPriority>) -> Self {
        Self {
            priorities,
            #[cfg(debug_assertions)]
            fully_executed_canisters: std::collections::BTreeSet::new(),
        }
    }

    /// Returns the priority for the given canister, or the default priority if not
    /// found.
    pub fn get(&self, canister_id: &CanisterId) -> &CanisterPriority {
        self.priorities
            .get(canister_id)
            .unwrap_or(&CanisterPriority::DEFAULT)
    }

    /// Returns the priority for the given canister, inserting the default priority
    /// if not found.
    pub fn get_mut(&mut self, canister_id: CanisterId) -> &mut CanisterPriority {
        self.priorities
            .entry(canister_id)
            .or_insert_with(|| CanisterPriority::DEFAULT)
    }

    /// Removes the priority of the given canister, essentially resetting it to the
    /// default priority.
    pub fn remove(&mut self, canister_id: &CanisterId) {
        self.priorities.remove(canister_id);
    }

    /// Removes the priority of `old_id` and applies it to `new_id`.
    pub fn rename_canister(&mut self, old_id: &CanisterId, new_id: CanisterId) {
        if let Some(priority) = self.priorities.remove(old_id) {
            self.priorities.insert(new_id, priority);
        }
    }

    /// Retains only the priorities for which the predicate returns `true`.
    pub(crate) fn retain(&mut self, f: impl FnMut(&CanisterId, &mut CanisterPriority) -> bool) {
        self.priorities.retain(f);
    }

    /// Iterates over the priorities, in ascending `CanisterId` order.
    pub fn iter(&self) -> impl Iterator<Item = (&CanisterId, &CanisterPriority)> {
        self.priorities.iter()
    }

    /// Iterates over the priorities, in ascending `CanisterId` order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&CanisterId, &mut CanisterPriority)> {
        self.priorities.iter_mut()
    }

    /// Returns the number of canister priorities in the schedule.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.priorities.len()
    }

    /// Retains only the scheduling priorities of the canisters hosted on this
    /// subnet after a split.
    pub(crate) fn split(&mut self, is_local_canister: impl Fn(CanisterId) -> bool) {
        self.priorities
            .retain(|canister_id, _| is_local_canister(*canister_id));
    }
}
