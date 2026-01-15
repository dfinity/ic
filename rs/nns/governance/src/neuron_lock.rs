//! This module defines mechanisms for locking neurons in order to prevent problematic interleaving
//! of neuron operations.
//!
//! The `LedgerUpdateLock` is a legacy mechanism, where the lock contains a `*mut Governance`
//! pointer. An unsafe block is needed to unlock the neuron. In addition, the pointer needs to be
//! `'static` in order for the lock to be used in async contexts. However, using `&'static mut` to
//! access global state is dangerous and should be avoided.
//!
//! The `NeuronAsyncLock` is a new mechanism that uses a `&'static LocalKey<RefCell<Governance>>` to
//! access the global state. This allows for safe access to the global state in async contexts.
//!
//! For sync methods, there is actually no need to acquire the lock, since it's impossible for the
//! lock to be persisted in any case anyway. In the future, a new method on the `Governance` struct
//! can be used to check whether a lock is held for a neuron. However, currently, in order to avoid
//! introducing a 3rd pattern for locking neurons, the recommendation is to keep using
//! `lock_neuron_for_command` with a `SyncCommand`.
//!
//! Note that it's OK for `NeuronAsyncLock` and `LedgerUpdateLock` to co-exist. If a
//! `NeuronAsyncLock` is held for a neuron, and another method tries to acquire a `LedgerUpdateLock`
//! for the same neuron, it will still fail as expected, and vice versa, since their underlying
//! storage is the same `in_flight_commands` map.
use crate::{
    governance::Governance,
    pb::v1::{
        GovernanceError,
        governance::{NeuronInFlightCommand, neuron_in_flight_command::Command},
        governance_error::ErrorType,
    },
};

use ic_cdk::println;
use ic_nns_common::pb::v1::NeuronId;
use std::{cell::RefCell, collections::hash_map::Entry, thread::LocalKey};

/// A lock for a neuron that is being updated. This lock can be used in asynchronous methods where a
/// `'static LocalKey<RefCell<Governance>>` is available instead of a `&'static mut Governance`.
pub(crate) struct NeuronAsyncLock {
    neuron_id: NeuronId,
    governance: &'static LocalKey<RefCell<Governance>>,
    retain: bool,
}

impl Drop for NeuronAsyncLock {
    fn drop(&mut self) {
        if self.retain {
            return;
        }
        // In the case of a panic, the state of the ledger account representing the neuron's stake
        // may be inconsistent with the internal state of governance.  In that case, we want to
        // prevent further operations with that neuron until the issue can be investigated and
        // resolved, which will require code changes.
        if ic_cdk::futures::is_recovering_from_trap() {
            return;
        }
        // The lock is released when the NeuronAsyncLock is dropped. This is done to ensure that the lock
        // is released even if the NeuronAsyncLock is not explicitly unlocked.
        self.governance.with_borrow_mut(|governance| {
            governance.unlock_neuron(self.neuron_id.id);
        });
    }
}

impl NeuronAsyncLock {
    /// Retains the lock even on drop.
    pub(crate) fn retain(&mut self) {
        self.retain = true;
    }
}

/// A single ongoing update for a single neuron.
/// Releases the lock when destroyed.
pub(crate) struct LedgerUpdateLock {
    nid: u64,
    gov: *mut Governance,
    // Retain this lock even on drop.
    retain: bool,
}

impl Drop for LedgerUpdateLock {
    fn drop(&mut self) {
        if self.retain {
            return;
        }
        // In the case of a panic, the state of the ledger account representing the neuron's stake
        // may be inconsistent with the internal state of governance.  In that case,
        // we want to prevent further operations with that neuron until the issue can be
        // investigated and resolved, which will require code changes.
        if ic_cdk::futures::is_recovering_from_trap() {
            return;
        }
        // It's always ok to dereference the governance when a LedgerUpdateLock
        // goes out of scope. Indeed, in the scope of any Governance method,
        // &self always remains alive. The 'mut' is not an issue, because
        // 'unlock_neuron' will verify that the lock exists.
        //
        // See "Recommendations for Using `unsafe` in the Governance canister" in canister.rs
        let gov: &mut Governance = unsafe { &mut *self.gov };
        gov.unlock_neuron(self.nid);
    }
}

impl LedgerUpdateLock {
    pub(crate) fn retain(&mut self) {
        self.retain = true;
    }
}

impl Governance {
    /// Acquires a neuron lock given a `&'static LocalKey<RefCell<Governance>>` within an async
    /// method, in order to make sure no other neuron methods interleave with the async method for
    /// the same neuron.
    ///
    /// This stores the in-flight operation in the proto so that, if anything
    /// goes wrong we can:
    ///
    /// 1 - Know what was happening.
    /// 2 - Reconcile the state post-upgrade, if necessary.
    ///
    /// No concurrent updates to this neuron's state are possible
    /// until the lock is released.
    ///
    /// ***** IMPORTANT *****
    /// The return value MUST be allocated to a variable with a name that is NOT
    /// "_" !
    ///
    /// The NeuronAsyncLock must remain alive for the entire duration of the
    /// ledger call. Quoting
    /// https://doc.rust-lang.org/book/ch18-03-pattern-syntax.html#ignoring-an-unused-variable-by-starting-its-name-with-_
    ///
    /// > Note that there is a subtle difference between using only _ and using
    /// > a name that starts with an underscore. The syntax _x still binds
    /// > the value to the variable, whereas _ doesn’t bind at all.
    ///
    /// What this means is that the expression
    /// ```text
    /// let _ = acquire_neuron_async_lock(...);
    /// ```
    /// is useless, because the `NeuronAsyncLock`` is a temporary object. It is constructed
    /// (and the lock is acquired), the immediately dropped (and the lock is released).
    ///
    /// However, the expression
    /// ```text
    /// let _my_lock = acquire_neuron_async_lock(...);
    /// ```
    /// will retain the lock for the entire scope.
    pub(crate) fn acquire_neuron_async_lock(
        governance: &'static LocalKey<RefCell<Self>>,
        neuron_id: NeuronId,
        timestamp: u64,
        command: Command,
    ) -> Result<NeuronAsyncLock, GovernanceError> {
        assert!(
            !matches!(command, Command::SyncCommand(_)),
            "SyncCommand is not supported"
        );
        let lock_acquired = governance.with_borrow_mut(|governance| {
            match governance.heap_data.in_flight_commands.entry(neuron_id.id) {
                Entry::Occupied(_) => false,
                Entry::Vacant(entry) => {
                    entry.insert(NeuronInFlightCommand {
                        command: Some(command),
                        timestamp,
                    });
                    true
                }
            }
        });
        if lock_acquired {
            Ok(NeuronAsyncLock {
                neuron_id,
                governance,
                retain: false,
            })
        } else {
            Err(GovernanceError::new_with_message(
                ErrorType::LedgerUpdateOngoing,
                "Neuron has an ongoing ledger update.",
            ))
        }
    }

    /// Locks a given neuron for a specific, signaling there is an ongoing
    /// ledger update.
    ///
    /// This stores the in-flight operation in the proto so that, if anything
    /// goes wrong we can:
    ///
    /// 1 - Know what was happening.
    /// 2 - Reconcile the state post-upgrade, if necessary.
    ///
    /// No concurrent updates to this neuron's state are possible
    /// until the lock is released.
    ///
    /// ***** IMPORTANT *****
    /// The return value MUST be allocated to a variable with a name that is NOT
    /// "_" !
    ///
    /// The LedgerUpdateLock must remain alive for the entire duration of the
    /// ledger call. Quoting
    /// https://doc.rust-lang.org/book/ch18-03-pattern-syntax.html#ignoring-an-unused-variable-by-starting-its-name-with-_
    ///
    /// > Note that there is a subtle difference between using only _ and using
    /// > a name that starts with an underscore. The syntax _x still binds
    /// > the value to the variable, whereas _ doesn’t bind at all.
    ///
    /// What this means is that the expression
    /// ```text
    /// let _ = lock_neuron_for_command(...);
    /// ```
    /// is useless, because the
    /// LedgerUpdateLock is a temporary object. It is constructed (and the lock
    /// is acquired), the immediately dropped (and the lock is released).
    ///
    /// However, the expression
    /// ```text
    /// let _my_lock = lock_neuron_for_command(...);
    /// ```
    /// will retain the lock for the entire scope.
    pub(crate) fn lock_neuron_for_command(
        &mut self,
        id: u64,
        command: NeuronInFlightCommand,
    ) -> Result<LedgerUpdateLock, GovernanceError> {
        if self.heap_data.in_flight_commands.contains_key(&id) {
            return Err(GovernanceError::new_with_message(
                ErrorType::LedgerUpdateOngoing,
                "Neuron has an ongoing ledger update.",
            ));
        }

        self.heap_data.in_flight_commands.insert(id, command);

        Ok(LedgerUpdateLock {
            nid: id,
            gov: self,
            retain: false,
        })
    }

    /// Unlocks a given neuron.
    fn unlock_neuron(&mut self, id: u64) {
        if self.heap_data.in_flight_commands.remove(&id).is_none() {
            println!(
                "Unexpected condition when unlocking neuron {}: the neuron was not \
                registered as 'in flight'",
                id
            );
        }
    }
}

#[cfg(test)]
#[path = "neuron_lock_tests.rs"]
mod tests;
