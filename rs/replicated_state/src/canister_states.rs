//! `CanisterStates`: a hot/cold-partitioned collection of [`CanisterState`]s.
//!
//! The set of all canisters hosted on a subnet is split into two collections:
//!
//!   * `hot`: canisters that may need round-level attention. The hot pool is
//!     intentionally a superset of "actually active": once a canister has been
//!     touched (via [`CanisterStates::get_mut`] or any other mutating accessor)
//!     it stays hot until explicitly demoted.
//!   * `cold`: canisters that are *definitely* idle, as defined by the pure
//!     predicate [`CanisterState::is_cold`].
//!
//! Promotion (cold → hot) is eager: it happens as a side effect of every
//! mutating accessor. Demotion (hot → cold) is conditional and explicit, via
//! [`CanisterStates::try_cool`] for single canisters or
//! [`CanisterStates::try_cool_all`] for a bulk pass.
//!
//! Internally, `CanisterStates` also maintains `ColdStats`, a small set of
//! aggregates over the cold pool that lets several aggregated queries (e.g.
//! [`CanisterStates::total_compute_allocation`],
//! [`CanisterStates::total_canister_memory_usage`],
//! [`CanisterStates::callback_count`]) become `O(|hot|)` instead of
//! `O(|all canisters|)`. These aggregates are an implementation detail: callers
//! always go through the public aggregator methods.

use crate::CanisterState;
use crate::replicated_state::MemoryTaken;
use ic_base_types::NumBytes;
use ic_types::CanisterId;
use ic_types_cycles::NominalCycles;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::iter::Peekable;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// O(1) aggregates over the canisters currently in the `cold` pool.
///
/// Maintained incrementally: every transition into / out of `cold` adds or
/// subtracts the contributing canister's values. The aggregates here are
/// expected to be a small enough set that the bookkeeping cost on each
/// transition is constant time and the resulting cost savings on the
/// `O(|all canisters|)` aggregate computations in `ReplicatedState` are
/// significant.
///
/// Crucially, `ColdStats` is *derived* state: it is recomputable from the
/// `cold` map at any time and is **not** persisted in checkpoints. It is
/// reconstructed when canisters are inserted (e.g. on checkpoint load).
///
/// Private to the module: external callers reach the same totals through
/// [`CanisterStates::total_compute_allocation`],
/// [`CanisterStates::total_canister_memory_usage`] and
/// [`CanisterStates::callback_count`], which transparently combine the cold
/// aggregate with an `O(|hot|)` pass over hot canisters.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct ColdStats {
    /// Sum of `ComputeAllocation::as_percent()` across cold canisters.
    total_compute_allocation_percent: u64,
    /// Sum of `memory_allocation().allocated_bytes(memory_usage())` (maximum of
    /// memory allocation and memory usage).
    execution_memory: NumBytes,
    /// Sum of `memory_usage()` (actual execution memory usage, ignoring memory
    /// allocation).
    memory_usage: NumBytes,
    /// Sum of `system_state.guaranteed_response_message_memory_usage()`.
    ///
    /// Cold canisters have no enqueued messages by `is_cold()`, but they can still
    /// hold guaranteed-response reservations, contributing to guaranteed-response
    /// message memory usage.
    guaranteed_response_message_memory: NumBytes,
    /// Sum of `wasm_custom_sections_memory_usage()`.
    wasm_custom_sections_memory: NumBytes,
    /// Sum of `canister_history_memory_usage()`.
    canister_history_memory: NumBytes,
    /// Sum of `ccm.unresponded_callback_count()` (which for cold canisters
    /// equals the number of guaranteed-response callbacks; best-effort
    /// callbacks force the canister into `hot`).
    callback_count: usize,
    /// Sum of `system_state.canister_metrics().consumed_cycles()`.
    ///
    /// Unlike the other aggregates, a cold canister's consumed cycles keep
    /// growing while it stays cold (e.g. storage charging via `for_each_mut`),
    /// but the sub-before / add-after bracketing around every cold-pool
    /// mutation keeps this sum consistent regardless.
    consumed_cycles: NominalCycles,
}

impl ColdStats {
    /// Adds the contribution of `canister` to the aggregates.
    fn add(&mut self, canister: &CanisterState) {
        self.total_compute_allocation_percent += canister.compute_allocation().as_percent();
        let memory_usage = canister.memory_usage();
        self.execution_memory += canister.memory_allocation().allocated_bytes(memory_usage);
        self.memory_usage += memory_usage;
        self.guaranteed_response_message_memory += canister
            .system_state
            .guaranteed_response_message_memory_usage();
        self.wasm_custom_sections_memory += canister.wasm_custom_sections_memory_usage();
        self.canister_history_memory += canister.canister_history_memory_usage();
        self.callback_count += canister
            .system_state
            .call_context_manager()
            .map_or(0, |ccm| ccm.unresponded_callback_count());
        self.consumed_cycles += canister.system_state.canister_metrics().consumed_cycles();
    }

    /// Subtracts the contribution of `canister` from the aggregates.
    fn sub(&mut self, canister: &CanisterState) {
        self.total_compute_allocation_percent -= canister.compute_allocation().as_percent();
        let memory_usage = canister.memory_usage();
        self.execution_memory -= canister.memory_allocation().allocated_bytes(memory_usage);
        self.memory_usage -= memory_usage;
        self.guaranteed_response_message_memory -= canister
            .system_state
            .guaranteed_response_message_memory_usage();
        self.wasm_custom_sections_memory -= canister.wasm_custom_sections_memory_usage();
        self.canister_history_memory -= canister.canister_history_memory_usage();
        self.callback_count -= canister
            .system_state
            .call_context_manager()
            .map_or(0, |ccm| ccm.unresponded_callback_count());
        self.consumed_cycles -= canister.system_state.canister_metrics().consumed_cycles();
    }

    /// Computes `ColdStats` from scratch over the provided cold canisters.
    /// Used to (re-)derive the aggregates, e.g. after loading from checkpoint
    /// and as a `debug_assert!` sanity check inside `debug_assert_invariants`.
    fn recompute<'a, I>(cold: I) -> Self
    where
        I: IntoIterator<Item = &'a Arc<CanisterState>>,
    {
        let mut stats = ColdStats::default();
        for c in cold {
            stats.add(c.as_ref());
        }
        stats
    }
}

/// Hot/cold-partitioned collection of canister states.
///
/// See the module-level docs for the overall design. The two underlying
/// `BTreeMaps` are disjoint at all times; merged iteration over them yields
/// `(canister_id, canister_state)` pairs in `CanisterId` order, exactly as
/// a flat `BTreeMap<CanisterId, Arc<CanisterState>>` would.
///
/// `PartialEq` and `ValidateEq` are derived: two `CanisterStates` are equal iff
/// they have the same partition (hot vs. cold) and the same `cold_stats`. This
/// makes the partition observable through equality assertions in tests.
///
/// # Invariants
///
/// The following invariants hold after **every** mutating operation and are
/// checked in debug builds by `debug_assert_invariants`:
///
/// 1. `hot` and `cold` pools are disjoint (no canister ID in both);
/// 2. every canister in the `cold` pool satisfies `CanisterState::is_cold()`;
/// 3. `cold_stats` matches a fresh recomputation over the `cold` pool.
///
/// Additionally, the **strict** partition invariant — that every canister in
/// the `hot` pool does *not* satisfy `is_cold()` — holds after
/// [`Self::try_cool_all`] /
/// [`crate::ReplicatedState::repartition_canister_states`], and is verified
/// during checkpoint validation by [`Self::validate_strict_split`]. Between
/// repartitioning passes the `hot` pool may contain canisters that have gone
/// quiet but have not yet been demoted; this is by design.
#[derive(Clone, Debug, Default, PartialEq, ValidateEq)]
pub struct CanisterStates {
    /// Canisters that may have round-level work or are recently active. Always
    /// scanned by per-round operations (scheduling, heartbeat enqueueing,
    /// timeout, queue GC, etc.).
    #[validate_eq(CompareWithValidateEq)]
    hot: BTreeMap<CanisterId, Arc<CanisterState>>,

    /// Canisters that are definitely idle (i.e. `CanisterState::is_cold()`
    /// returns `true`). Operations that need to visit every canister still
    /// need to consider them; per-round operations should skip them.
    #[validate_eq(CompareWithValidateEq)]
    cold: BTreeMap<CanisterId, Arc<CanisterState>>,

    /// O(1) aggregates over `cold` canisters. See [`ColdStats`].
    cold_stats: ColdStats,
}

impl CanisterStates {
    /// Builds a `CanisterStates` from a flat map, classifying canisters via
    /// [`CanisterState::is_cold`].
    ///
    /// Used at checkpoint load time and anywhere else we need to lift a flat
    /// `BTreeMap` representation into a `CanisterStates`.
    pub fn new(canisters: BTreeMap<CanisterId, Arc<CanisterState>>) -> Self {
        let mut hot = BTreeMap::new();
        let mut cold = BTreeMap::new();
        let mut cold_stats = ColdStats::default();
        for (id, canister) in canisters {
            if canister.is_cold() {
                cold_stats.add(canister.as_ref());
                cold.insert(id, canister);
            } else {
                hot.insert(id, canister);
            }
        }
        let states = Self {
            hot,
            cold,
            cold_stats,
        };
        states.debug_assert_invariants();
        states
    }

    /// Returns a reference to the canister with the given ID, if present, from
    /// either pool.
    pub fn get(&self, id: &CanisterId) -> Option<&Arc<CanisterState>> {
        self.hot.get(id).or_else(|| self.cold.get(id))
    }

    /// Returns a mutable reference to the `Arc<CanisterState>` in `hot`. If the
    /// canister is currently in `cold`, it is first promoted (moved to `hot`, with
    /// `cold_stats` updated accordingly).
    ///
    /// This is the back door used by all mutating accessors on `ReplicatedState`.
    /// Anyone holding the returned `&mut Arc<CanisterState>` may freely mutate the
    /// canister via `Arc::make_mut`; the canister will remain in `hot` until
    /// explicitly re-classified.
    ///
    /// Idempotent and `O(log n)`.
    pub fn get_mut(&mut self, id: &CanisterId) -> Option<&mut Arc<CanisterState>> {
        // Optimization: the `hot` pool is likely much smaller. And we're most likely
        // dealing with a hot canister to begin with.
        match self.hot.entry(*id) {
            // In the `hot` pool, return it.
            Entry::Occupied(entry) => Some(entry.into_mut()),

            Entry::Vacant(entry) => {
                let canister = self.cold.remove(id)?;
                // Was in the `cold` pool, update the stats and promote it.
                self.cold_stats.sub(canister.as_ref());
                let canister = entry.insert(canister);
                // Unfortunately, the borrow checker won't let us do this here.
                // self.debug_assert_invariants();
                Some(canister)
            }
        }
    }

    /// Returns true iff the given canister is present in either pool.
    pub fn contains_key(&self, id: &CanisterId) -> bool {
        self.hot.contains_key(id) || self.cold.contains_key(id)
    }

    /// Returns the total number of canisters (`hot` plus `cold`).
    pub fn len(&self) -> usize {
        self.hot.len() + self.cold.len()
    }

    /// Returns the number of canisters in the `hot` pool (which may or may not be
    /// actually hot).
    pub fn hot_len(&self) -> usize {
        self.hot.len()
    }

    /// Returns true iff there are no canisters at all.
    pub fn is_empty(&self) -> bool {
        self.hot.is_empty() && self.cold.is_empty()
    }

    /// Inserts a canister into the appropriate pool. If a canister with this
    /// ID was already present (in either pool), it is replaced and returned;
    /// `cold_stats` is adjusted accordingly.
    pub fn insert(&mut self, canister: Arc<CanisterState>) -> Option<Arc<CanisterState>> {
        // Drop any previous entry first so `cold_stats` doesn't double-count
        // when we transition from / to the cold pool.
        let id = canister.canister_id();
        let prev = self.remove(&id);

        if canister.is_cold() {
            self.cold_stats.add(canister.as_ref());
            self.cold.insert(id, canister);
        } else {
            self.hot.insert(id, canister);
        }
        self.debug_assert_invariants();
        prev
    }

    /// Removes and returns the canister with the given ID from whichever pool
    /// it is in. Updates `cold_stats` if the canister was in `cold`.
    pub fn remove(&mut self, id: &CanisterId) -> Option<Arc<CanisterState>> {
        let removed = if let Some(canister) = self.hot.remove(id) {
            Some(canister)
        } else if let Some(canister) = self.cold.remove(id) {
            self.cold_stats.sub(canister.as_ref());
            Some(canister)
        } else {
            None
        };
        self.debug_assert_invariants();
        removed
    }

    /// Re-evaluates `is_cold()` for the given canister and, if true, moves the
    /// canister from `hot` to `cold`, updating `cold_stats`. No-op if the canister
    /// is not present, already in `cold`, or not cold.
    ///
    /// Returns true iff a transition (hot → cold) actually happened.
    pub fn try_cool(&mut self, id: &CanisterId) -> bool {
        let cooled = match self.hot.entry(*id) {
            Entry::Occupied(entry) if entry.get().is_cold() => {
                let canister = entry.remove();
                self.cold_stats.add(canister.as_ref());
                self.cold.insert(*id, canister);
                true
            }

            // Canister should remain in the `hot` pool.
            Entry::Occupied(_) => false,

            // Canister is not in the `hot` pool.
            Entry::Vacant(_) => false,
        };
        self.debug_assert_invariants();
        cooled
    }

    /// Demotes every canister currently in `hot` that satisfies `is_cold()`. Only
    /// walks the `hot` pool — assumes that, by mutation discipline, every canister
    /// already in `cold` still satisfies `is_cold()`.
    ///
    /// This is the cheap, frequent operation, called at the end of every round and
    /// before checkpoint creation to demote canisters that went quiet during the
    /// round back into `cold`.
    ///
    /// Complexity: `O(|hot|)`.
    pub fn try_cool_all(&mut self) {
        self.cold.extend(self.hot.extract_if(.., |_, canister| {
            if canister.is_cold() {
                self.cold_stats.add(canister.as_ref());
                true
            } else {
                false
            }
        }));
        self.debug_assert_invariants();
    }

    /// Read-only iterator over the `hot` pool only.
    pub fn hot_iter(&self) -> impl Iterator<Item = (&CanisterId, &Arc<CanisterState>)> {
        self.hot.iter()
    }

    /// Read-only iterator over canister state references in the `hot` pool only.
    pub fn hot_values(&self) -> impl Iterator<Item = &Arc<CanisterState>> {
        self.hot.values()
    }

    /// Mutable iterator over the `hot` pool only. Yielded `&mut Arc<CanisterState>`
    /// values may be freely mutated; the canister stays in `hot`.
    ///
    /// Callers that need to mutate cold canisters should go through
    /// [`Self::for_each_mut`], but be aware that it's significantly more expensive.
    pub fn hot_values_mut(&mut self) -> impl Iterator<Item = &mut Arc<CanisterState>> {
        self.hot.values_mut()
    }

    /// Sorted merged iterator over all `(canister_id, canister_state)` pairs (hot
    /// and cold).
    pub fn all_iter(&self) -> Iter<'_> {
        Iter {
            hot: self.hot.iter().peekable(),
            cold: self.cold.iter().peekable(),
        }
    }

    /// Sorted merged iterator over all canister IDs (hot and cold).
    pub fn all_keys(&self) -> impl Iterator<Item = &CanisterId> {
        self.all_iter().map(|(id, _)| id)
    }

    /// Merged iterator over all canister states (hot and cold), sorted by
    /// `CanisterId`.
    pub fn all_values(&self) -> impl Iterator<Item = &Arc<CanisterState>> {
        self.all_iter().map(|(_, c)| c)
    }

    /// Visits every canister (hot and cold) and runs `f` against it, then
    /// re-establishes strict hot/cold partitioning.
    ///
    /// This is the safe way to perform "touch every canister" loops (storage
    /// charging, checkpoint write-out, …) that may legitimately mutate cold
    /// canisters in ways affecting [`CanisterState::is_cold`] *or* any field
    /// aggregated in `ColdStats` (`compute_allocation`, `memory_allocation`,
    /// canister history size, callbacks).
    ///
    /// Iterates the hot pool followed by the cold pool — i.e. canisters are
    /// **not** yielded in `CanisterId` order — but every canister is visited
    /// exactly once. Cost is `O(|hot| + |cold|)`, with a small constant per
    /// cold canister for the `cold_stats` bookkeeping.
    pub fn for_each_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&CanisterId, &mut Arc<CanisterState>),
    {
        // Hot pool: just run the closure. `try_cool_all` below will demote
        // any canister that became cold.
        for (id, canister) in self.hot.iter_mut() {
            f(id, canister);
        }

        // Cold pool: iterate in place, removing all canisters that are no longer cold
        // after calling `f` and moving them to `hot`. Because `f` may also alter the
        // canister's stats, conservatively subtract them from `cold_stats` then add
        // them back iff the canister stayed cold.
        self.hot.extend(self.cold.extract_if(.., |id, canister| {
            self.cold_stats.sub(canister.as_ref());
            f(id, canister);
            if canister.is_cold() {
                // Restore the (potentially changed) stats and retain it in `cold`.
                self.cold_stats.add(canister.as_ref());
                false
            } else {
                // Hot canister, promote it.
                true
            }
        }));

        // Demote all canisters that are now cold.
        self.try_cool_all();
        self.debug_assert_invariants();
    }

    /// Fallible variant of [`Self::for_each_mut`]: stops at the first `Err`
    /// returned by `f` and propagates it, but always preserves the invariants.
    pub fn try_for_each_mut<F, E>(&mut self, mut f: F) -> Result<(), E>
    where
        F: FnMut(&CanisterId, &mut Arc<CanisterState>) -> Result<(), E>,
    {
        use std::ops::Bound::*;

        // Hot pool: short-circuit on the first error.
        let mut result = self.hot.iter_mut().try_for_each(|(id, c)| f(id, c));

        if result.is_ok() {
            // Cold pool, pass 1: mutate the canisters in place, short-circuiting on error.
            let mut cold_iter = self.cold.iter_mut();
            result = cold_iter.try_for_each(|(id, canister)| {
                // Conservatively subtract each canister's initial stats from `cold_stats` and
                // add back the (possibly updated) stats, to keep `cold_stats` consistent with
                // `cold`.
                self.cold_stats.sub(canister.as_ref());
                let result = f(id, canister);
                self.cold_stats.add(canister.as_ref());
                result
            });
            // Upper bound for pass 2, iff we short-circuited.
            let end = cold_iter.next().map_or(Unbounded, |(id, _)| Excluded(*id));

            // Cold pool, pass 2: promote all canisters that are no longer cold, adjusting
            // `cold_stats` as we go.
            self.hot
                .extend(self.cold.extract_if((Unbounded, end), |_, canister| {
                    if canister.is_cold() {
                        false
                    } else {
                        self.cold_stats.sub(canister.as_ref());
                        true
                    }
                }));
        }

        // Demote all canisters that are now cold.
        self.try_cool_all();
        self.debug_assert_invariants();
        result
    }

    /// Retains only the canisters for which the predicate returns true, updating
    /// `cold_stats` to account for any cold canister that was removed.
    ///
    /// Iterates both pools.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&CanisterId, &Arc<CanisterState>) -> bool,
    {
        self.hot.retain(|id, c| f(id, c));
        self.cold.retain(|id, c| {
            if f(id, c) {
                true
            } else {
                self.cold_stats.sub(c.as_ref());
                false
            }
        });
        self.debug_assert_invariants();
    }

    /// Returns the total reserved compute allocation (as a sum of percentage
    /// points) across all canisters.
    ///
    /// `O(|hot canisters|)` thanks to the precomputed cold-pool aggregate.
    pub fn total_compute_allocation(&self) -> u64 {
        let hot: u64 = self
            .hot
            .values()
            .map(|canister| canister.compute_allocation().as_percent())
            .sum();
        hot + self.cold_stats.total_compute_allocation_percent
    }

    /// Returns the total number of callbacks registered across all canisters.
    ///
    /// `O(|hot canisters|)` thanks to the precomputed cold-pool aggregate.
    pub fn callback_count(&self) -> usize {
        let hot: usize = self
            .hot
            .values()
            .map(|canister| {
                canister
                    .system_state
                    .call_context_manager()
                    .map_or(0, |ccm| ccm.unresponded_callback_count())
            })
            .sum();
        hot + self.cold_stats.callback_count
    }

    /// Returns the total number of cycles consumed by all canisters.
    ///
    /// `O(|hot canisters|)` thanks to the precomputed cold-pool aggregate.
    pub fn total_consumed_cycles(&self) -> NominalCycles {
        let hot = self
            .hot
            .values()
            .fold(NominalCycles::zero(), |acc, canister| {
                acc + canister.system_state.canister_metrics().consumed_cycles()
            });
        hot + self.cold_stats.consumed_cycles
    }

    /// Returns the total memory usage of all canisters, including message memory.
    ///
    /// `O(|hot canisters|)` thanks to the precomputed cold-pool aggregate.
    pub fn total_canister_memory_usage(&self) -> NumBytes {
        let hot: NumBytes = self
            .hot
            .values()
            .map(|canister| canister.memory_usage() + canister.message_memory_usage().total())
            .sum();
        // Cold canisters contribute their execution memory plus any
        // guaranteed-response message memory (reservations).
        hot + self.cold_stats.memory_usage + self.cold_stats.guaranteed_response_message_memory
    }

    /// Returns the total guaranteed-response message memory (including
    /// reservations) across all canisters.
    ///
    /// `pub(crate)` because it does **not** include subnet queues. Call
    /// `ReplicatedState::guaranteed_response_message_memory_taken` for the actual
    /// subnet-wide guaranteed-response message memory usage.
    ///
    /// `O(|hot canisters|)` thanks to the precomputed cold-pool aggregate.
    pub(crate) fn guaranteed_response_message_memory_taken(&self) -> NumBytes {
        let hot: NumBytes = self
            .hot
            .values()
            .map(|canister| {
                canister
                    .system_state
                    .guaranteed_response_message_memory_usage()
            })
            .sum();
        hot + self.cold_stats.guaranteed_response_message_memory
    }

    /// Returns the total best-effort message memory across all canisters.
    ///
    /// `pub(crate)` because it does **not** include subnet queues. Call
    /// `ReplicatedState::best_effort_message_memory_taken` for the actual
    /// subnet-wide best-effort message memory usage.
    ///
    /// `O(|hot canisters|)` — cold canisters by definition use no best-effort
    /// message memory (see `CanisterState::is_cold`).
    pub(crate) fn best_effort_message_memory_taken(&self) -> NumBytes {
        self.hot
            .values()
            .map(|canister| canister.system_state.best_effort_message_memory_usage())
            .sum()
    }

    /// Computes the per-resource [`MemoryTaken`] aggregate across all canisters.
    ///
    /// `pub(crate)` because it does **not** include subnet queues. Call
    /// `ReplicatedState::memory_taken` for the actual subnet-wide memory stats.
    ///
    /// `O(|hot canisters|)` thanks to the precomputed cold-pool aggregate.
    pub(crate) fn memory_taken(&self) -> MemoryTaken {
        // Start from the pre-aggregated `cold_stats`.
        let cold = &self.cold_stats;
        let mut memory_taken = MemoryTaken {
            execution: cold.execution_memory,
            guaranteed_response_messages: cold.guaranteed_response_message_memory,
            // Cold canisters have no messages in their queues.
            best_effort_messages: NumBytes::new(0),
            wasm_custom_sections: cold.wasm_custom_sections_memory,
            canister_history: cold.canister_history_memory,
        };

        // Add the hot pool contributions, one canister at a time.
        for canister in self.hot.values() {
            memory_taken.execution += canister.memory_allocated_bytes();
            memory_taken.guaranteed_response_messages += canister
                .system_state
                .guaranteed_response_message_memory_usage();
            memory_taken.best_effort_messages +=
                canister.system_state.best_effort_message_memory_usage();
            memory_taken.wasm_custom_sections += canister.wasm_custom_sections_memory_usage();
            memory_taken.canister_history += canister.canister_history_memory_usage();
        }

        memory_taken
    }

    /// Validates that the current hot/cold partition matches the canonical "strict"
    /// split that [`CanisterStates::new`] would produce over the same set of
    /// canisters:
    ///  * every canister in the `cold` pool satisfies `is_cold()`; and
    ///  * every canister in the `hot`  pool does **not** satisfy `is_cold()`.
    ///
    /// Intended for checkpoint validation, to assert that the state was
    /// repartitioned before checkpointing, so that replicas continuing through a
    /// checkpoint and replicas restarting from it have identical partitioning.
    ///
    /// Complexity: `O(|all canisters|)`.
    pub fn validate_strict_split(&self) -> Result<(), String> {
        if let Some((id, _)) = self.hot.iter().find(|(_, c)| c.is_cold()) {
            return Err(format!("canister {id} in `hot` pool satisfies `is_cold()`"));
        }
        if let Some((id, _)) = self.cold.iter().find(|(_, c)| !c.is_cold()) {
            return Err(format!(
                "canister {id} in `cold` pool does not satisfy `is_cold()`"
            ));
        }
        Ok(())
    }

    /// Debug-only consistency check, called at the end of every mutating operation.
    /// Verifies invariants (1)–(3) listed under [`CanisterStates`].
    ///
    /// Also see [`Self::validate_strict_split`] for the stricter validation applied
    /// during checkpoint validation.
    fn debug_assert_invariants(&self) {
        debug_assert!(
            self.hot.keys().all(|id| !self.cold.contains_key(id)),
            "hot and cold pools overlap"
        );
        debug_assert!(
            self.cold.values().all(|c| c.is_cold()),
            "cold pool contains a canister that is not cold",
        );
        debug_assert_eq!(
            ColdStats::recompute(self.cold.values()),
            self.cold_stats,
            "cold_stats is out of sync with the cold pool"
        );
    }
}

/// Iterator returned by [`CanisterStates::all_iter`]. Merge-yields entries from
/// the `hot` and `cold` pools in `CanisterId` order.
pub struct Iter<'a> {
    hot: Peekable<std::collections::btree_map::Iter<'a, CanisterId, Arc<CanisterState>>>,
    cold: Peekable<std::collections::btree_map::Iter<'a, CanisterId, Arc<CanisterState>>>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a CanisterId, &'a Arc<CanisterState>);

    fn next(&mut self) -> Option<Self::Item> {
        match (self.hot.peek(), self.cold.peek()) {
            (Some((hot_id, _)), Some((cold_id, _))) => {
                if hot_id <= cold_id {
                    self.hot.next()
                } else {
                    self.cold.next()
                }
            }
            (Some(_), None) => self.hot.next(),
            (None, Some(_)) => self.cold.next(),
            (None, None) => None,
        }
    }
}
