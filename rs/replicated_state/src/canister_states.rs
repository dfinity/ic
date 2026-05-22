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
//! This module currently only provides the partitioning machinery. The
//! `ReplicatedState` integration and the `O(1)` cold-pool aggregates are
//! introduced in follow-up changes; right now `CanisterStates` is not yet
//! wired into `ReplicatedState`.

use crate::CanisterState;
use ic_types::CanisterId;
use ic_validate_eq::ValidateEq;
use ic_validate_eq_derive::ValidateEq;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::iter::Peekable;
use std::sync::Arc;

#[cfg(test)]
mod tests;

/// Hot/cold-partitioned collection of canister states.
///
/// See the module-level docs for the overall design. The two underlying
/// `BTreeMaps` are disjoint at all times; merged iteration over them yields
/// `(canister_id, canister_state)` pairs in `CanisterId` order, exactly as
/// a flat `BTreeMap<CanisterId, Arc<CanisterState>>` would.
///
/// `PartialEq` and `ValidateEq` are derived: two `CanisterStates` are equal iff
/// they have the same partition (hot vs. cold). This makes the partition
/// observable through equality assertions in tests.
///
/// # Invariants
///
/// The following invariants hold after **every** mutating operation and are
/// checked in debug builds by `debug_assert_invariants`:
///
/// 1. `hot` and `cold` pools are disjoint (no canister ID in both);
/// 2. every canister in the `cold` pool satisfies `CanisterState::is_cold()`.
///
/// Additionally, the **strict** partition invariant — that every canister in
/// the `hot` pool does *not* satisfy `is_cold()` — holds after
/// [`Self::try_cool_all`] and is verified by [`Self::validate_strict_split`].
/// Between repartitioning passes the `hot` pool may contain canisters that
/// have gone quiet but have not yet been demoted; this is by design.
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
        for (id, canister) in canisters {
            if canister.is_cold() {
                cold.insert(id, canister);
            } else {
                hot.insert(id, canister);
            }
        }
        let states = Self { hot, cold };
        states.debug_assert_invariants();
        states
    }

    /// Returns a reference to the canister with the given ID, if present, from
    /// either pool.
    pub fn get(&self, id: &CanisterId) -> Option<&Arc<CanisterState>> {
        self.hot.get(id).or_else(|| self.cold.get(id))
    }

    /// Returns a mutable reference to the `Arc<CanisterState>` in `hot`. If the
    /// canister is currently in `cold`, it is first promoted (moved to `hot`).
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
                if let Some(canister) = self.cold.remove(id) {
                    // Was in the `cold` pool, promote it.
                    let canister = entry.insert(canister);
                    // Unfortunately, the borrow checker won't let us do this here.
                    // self.debug_assert_invariants();
                    Some(canister)
                } else {
                    // Also not in the `cold` pool, so not present.
                    None
                }
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

    /// Returns true iff there are no canisters at all.
    pub fn is_empty(&self) -> bool {
        self.hot.is_empty() && self.cold.is_empty()
    }

    /// Inserts a canister into the appropriate pool. If a canister with this
    /// ID was already present (in either pool), it is replaced and returned.
    pub fn insert(&mut self, canister: Arc<CanisterState>) -> Option<Arc<CanisterState>> {
        let id = canister.canister_id();
        // Drop any previous entry first so that the partition reflects the
        // freshly-inserted canister's `is_cold()` regardless of where the
        // old entry lived.
        let prev = self.remove(&id);

        if canister.is_cold() {
            self.cold.insert(id, canister);
        } else {
            self.hot.insert(id, canister);
        }
        self.debug_assert_invariants();
        prev
    }

    /// Removes and returns the canister with the given ID from whichever pool
    /// it is in.
    pub fn remove(&mut self, id: &CanisterId) -> Option<Arc<CanisterState>> {
        let removed = self.hot.remove(id).or_else(|| self.cold.remove(id));
        self.debug_assert_invariants();
        removed
    }

    /// Re-evaluates `is_cold()` for the given canister and, if true, moves the
    /// canister from `hot` to `cold`. No-op if the canister is not present,
    /// already in `cold`, or not cold.
    ///
    /// Returns true iff a transition (hot → cold) actually happened.
    pub fn try_cool(&mut self, id: &CanisterId) -> bool {
        let cooled = match self.hot.entry(*id) {
            Entry::Occupied(entry) if entry.get().is_cold() => {
                let canister = entry.remove();
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
        let to_cool: Vec<CanisterId> = self
            .hot
            .iter()
            .filter(|(_, canister)| canister.is_cold())
            .map(|(id, _)| *id)
            .collect();
        for id in to_cool {
            let canister = self.hot.remove(&id).unwrap();
            self.cold.insert(id, canister);
        }
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
    /// re-establishes the hot/cold partition.
    ///
    /// This is the safe way to perform "touch every canister" loops (storage
    /// charging, checkpoint write-out, …) that may legitimately mutate cold
    /// canisters in ways affecting [`CanisterState::is_cold`].
    ///
    /// Iterates the hot pool followed by the cold pool — i.e. canisters are
    /// **not** yielded in `CanisterId` order — but every canister is visited
    /// exactly once. Cost is `O(|hot| + |cold|)`.
    pub fn for_each_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&CanisterId, &mut Arc<CanisterState>),
    {
        // Hot pool: just run the closure. `try_cool_all` below will demote
        // any canister that became cold.
        for (id, canister) in self.hot.iter_mut() {
            f(id, canister);
        }

        // Cold pool: iterate in place. The closure may flip the canister to
        // non-cold, in which case we promote it to `hot` after the loop.
        let mut to_promote: Vec<CanisterId> = Vec::new();
        for (id, canister) in self.cold.iter_mut() {
            f(id, canister);
            if !canister.is_cold() {
                to_promote.push(*id);
            }
        }
        for id in to_promote {
            let canister = self.cold.remove(&id).unwrap();
            self.hot.insert(id, canister);
        }

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
        let mut result = Ok(());

        // Hot pool: short-circuit on the first error.
        for (id, canister) in self.hot.iter_mut() {
            if let Err(e) = f(id, canister) {
                result = Err(e);
                break;
            }
        }

        // Cold pool: same in-place strategy as `for_each_mut`, but short-circuit
        // on `Err`. We always preserve the partition for the canister we were
        // visiting when the error occurred, then propagate the error.
        let mut to_promote: Vec<CanisterId> = Vec::new();
        if result.is_ok() {
            for (id, canister) in self.cold.iter_mut() {
                let res = f(id, canister);
                if !canister.is_cold() {
                    to_promote.push(*id);
                }
                if let Err(e) = res {
                    result = Err(e);
                    break;
                }
            }
        }
        for id in to_promote {
            let canister = self.cold.remove(&id).unwrap();
            self.hot.insert(id, canister);
        }

        // Demote all canisters that are now cold.
        self.try_cool_all();
        self.debug_assert_invariants();
        result
    }

    /// Retains only the canisters for which the predicate returns true.
    ///
    /// Iterates both pools.
    pub fn retain<F>(&mut self, f: F)
    where
        F: Fn(&CanisterId, &Arc<CanisterState>) -> bool,
    {
        self.hot.retain(|id, c| f(id, c));
        self.cold.retain(|id, c| f(id, c));
        self.debug_assert_invariants();
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
    /// Verifies invariants (1)–(2) listed under [`CanisterStates`].
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
