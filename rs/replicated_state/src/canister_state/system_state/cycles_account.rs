//! This module contains the `CyclesAccount` which is responsible for
//! maintaining the cycles account of each canister.
//!
//! A canister has an associated cycles balance, and may `send` a part of
//! this cycles balance to another canister
//! In addition to sending cycles to another canister, a canister `spend`s
//! cycles in the following three ways:
//! a) executing messages,
//! b) sending messages to other canisters,
//! c) storing data over time/rounds
//! Each of the above spending is done in three phases:
//! 1. reserving maximum cycles the operation can require
//! 2. executing the operation and return `cycles_spent`
//! 3. reimburse the canister with `cycles_reserved` - `cycles_spent`

use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_types::{nominal_cycles::NominalCycles, Cycles};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CyclesAccountError {
    /// Canister is out of cycles.
    CanisterOutOfCycles {
        available: Cycles,
        requested: Cycles,
    },
}

impl std::error::Error for CyclesAccountError {}

impl std::fmt::Display for CyclesAccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CyclesAccountError::CanisterOutOfCycles {
                available,
                requested,
            } => write!(
                f,
                "Currently available cycles {}, but {} was requested",
                available, requested
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
/// Cycles account
///
/// It should be used whenever the canister is to be charged for using system
/// resources (like CPU, memory, network bandwidth) as well as for charging for
/// allocation of resources.
pub struct CyclesAccount {
    /// The current canister's cycles balance.
    cycles_balance: Cycles,
    // TODO(EXC-173): Refactoring the cycles account.
    /// Number of cycles consumed since the beginning of the replica.
    /// Used to update the metric `consumed_cycles_since_replica_started`
    /// at the end of every execution round.
    pub consumed_cycles_since_replica_started: NominalCycles,
}

impl CyclesAccount {
    pub fn new(initial_cycles: Cycles) -> Self {
        Self {
            cycles_balance: initial_cycles,
            consumed_cycles_since_replica_started: Default::default(),
        }
    }

    /// Returns the current cycles balance of the canister.
    pub fn cycles_balance(&self) -> Cycles {
        self.cycles_balance
    }

    /// Subtracts `cycles` worth of cycles from the canister's balance as long
    /// as there's enough above the provided `threshold`. This call should be
    /// used when the withdrawn cycles are sent somewhere else.
    pub fn withdraw_with_threshold(
        &mut self,
        cycles: Cycles,
        threshold: Cycles,
    ) -> Result<(), CyclesAccountError> {
        let cycles_available = if self.cycles_balance() > threshold {
            self.cycles_balance() - threshold
        } else {
            Cycles::from(0)
        };

        if cycles > cycles_available {
            return Err(CyclesAccountError::CanisterOutOfCycles {
                available: cycles_available,
                requested: cycles,
            });
        }

        self.cycles_balance -= cycles;
        Ok(())
    }

    /// Subtracts and consumes the cycles. This call should be used when the
    /// cycles are not being sent somewhere else.
    pub fn consume_with_threshold(
        &mut self,
        cycles: Cycles,
        threshold: Cycles,
    ) -> Result<(), CyclesAccountError> {
        self.withdraw_with_threshold(cycles, threshold).map(|()| {
            self.consumed_cycles_since_replica_started += NominalCycles::from_cycles(cycles)
        })
    }

    /// Adds `cycles` to the canister's balance.
    pub fn add_cycles(&mut self, cycles_to_add: Cycles) {
        self.cycles_balance += cycles_to_add;
    }

    pub fn refund_cycles(&mut self, cycles_to_refund: Cycles) {
        self.cycles_balance += cycles_to_refund;
        self.consumed_cycles_since_replica_started -= NominalCycles::from_cycles(cycles_to_refund);
    }

    /// Note that this function is made public to facilitate some logistic in
    /// tests.
    #[doc(hidden)]
    pub fn set_balance(&mut self, cycles: Cycles) {
        self.cycles_balance = cycles;
    }
}

impl From<&CyclesAccount> for pb::CyclesAccount {
    fn from(item: &CyclesAccount) -> Self {
        Self {
            cycles_balance: item.cycles_balance.into(),
        }
    }
}

impl From<pb::CyclesAccount> for CyclesAccount {
    fn from(value: pb::CyclesAccount) -> Self {
        Self {
            cycles_balance: Cycles::from(&value.cycles_balance),
            // TODO(EXC-173): Refactoring the cycles account.
            // Clearing up the tech debt mentioned above, will remove this field and
            // directly update the one from CanisterMetrics.
            // After loading CyclesAccount from checkpoint, we set this field
            // to the proper value which is held by `CanisterStateBits`
            consumed_cycles_since_replica_started: Default::default(),
        }
    }
}
