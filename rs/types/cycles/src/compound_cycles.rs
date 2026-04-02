use crate::{
    cycles::Cycles,
    cycles_cost_schedule::CanisterCyclesCostSchedule,
    cycles_use_case::{CyclesUseCase, CyclesUseCaseKind},
    nominal_cycles::NominalCycles,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

/// `CompoundCycles` holds the information related to updating the canister's
/// balance as well as metrics related to resource usage. The former
/// part will be referred to as "real" and the latter as the "nominal"
/// cycles amount, represented respectively by the `Cycles` and `NominalCycles`
/// types.
///
/// It encapsulates how the `CyclesUseCase` and `CanisterCyclesCostSchedule`
/// on the IC affect the real and nominal parts, abstracting it away from
/// callers that need to perform these updates at the various places where
/// cycles accounting is performed. Callers would only need to retrieve
/// the real and nominal parts via the `real()` and `nominal()` methods
/// provided and update the respective parts of the `ReplicatedState` where
/// these are kept.
///
/// E.g. one could do the following:
///
/// ```
/// use ic_types_cycles::{
///     CanisterCyclesCostSchedule, CompoundCycles, Cycles, CyclesUseCase,
///     CyclesUseCaseKind, Instructions, NominalCycles, NominalCyclesTesting,
/// };
/// use std::collections::BTreeMap;
///
/// let mut balance = Cycles::new(10);
///
/// let mut metrics = BTreeMap::new();
/// metrics.insert(CyclesUseCase::Instructions, NominalCycles::new(5));
///
/// let cc_instructions = CompoundCycles::<Instructions>::new(
///     Cycles::new(20), CanisterCyclesCostSchedule::Normal,
/// );
///
/// balance += cc_instructions.real();
/// *metrics
///     .entry(Instructions::cycles_use_case())
///     .or_insert_with(|| NominalCycles::zero()) += cc_instructions.nominal();
///
/// assert_eq!(balance, Cycles::new(30));
/// assert_eq!(
///     metrics.get(&Instructions::cycles_use_case()).unwrap(),
///     &NominalCycles::new(25),
/// );
/// ```
///
/// Extra type-safety is added via use of generics and phantom data to enforce
/// that arithmetic operations can only be performed on amounts that were
/// created for the same `CyclesUseCase` and `CanisterCyclesCostSchedule`.
///
/// E.g. the following code would not compile:
///
/// ```compile_fail
/// use ic_types_cycles::{
///     CompoundCycles, Cycles, Instructions, Memory, CanisterCyclesCostSchedule,
/// };
///
/// let cc_instructions = CompoundCycles::<Instructions>::new(
///     Cycles::new(10), CanisterCyclesCostSchedule::Normal,
/// );
/// let cc_memory = CompoundCycles::<Memory>::new(
///     Cycles::new(20), CanisterCyclesCostSchedule::Normal,
/// );
///
/// let total = cc_instructions + cc_memory;
/// assert_eq!(total.real(), Cycles::new(30));
/// ```
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Serialize, Deserialize)]
pub struct CompoundCycles<T: CyclesUseCaseKind> {
    real: Cycles,
    nominal: NominalCycles,
    _cycles_use_case_marker: PhantomData<T>,
}

impl<T: CyclesUseCaseKind> CompoundCycles<T> {
    pub fn new(amount: Cycles, cost_schedule: CanisterCyclesCostSchedule) -> Self {
        let use_case = T::cycles_use_case();
        let amount = match (use_case, cost_schedule) {
            (_, CanisterCyclesCostSchedule::Normal)
            // NonConsumed represents the amounts attached on inter-canister
            // calls and it's removed from a canister's balance regardless of
            // cost_schedule.
            | (CyclesUseCase::NonConsumed, CanisterCyclesCostSchedule::Free)
            // BurnedCycles represents the amount requested explicitly to be
            // burned via `ic0.cyles_burn` and it's removed from the balance
            // regardless of cost_schedule. 
            | (CyclesUseCase::BurnedCycles, CanisterCyclesCostSchedule::Free)
            // DeletedCanisters represents the amount lost if the canister is
            // deleted and it's lost regardless of cost_schedule.
            | (CyclesUseCase::DeletedCanisters, CanisterCyclesCostSchedule::Free) => amount,
            // DroppedMessages represents the amount that's lost if a bounded wait
            // response is dropped and it's lost regardless of cost_schedule.
            (CyclesUseCase::DroppedMessages, CanisterCyclesCostSchedule::Free) => amount,
            (CyclesUseCase::Memory, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::ComputeAllocation, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::IngressInduction, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::Instructions, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::RequestAndResponseTransmission, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::Uninstall, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::CanisterCreation, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::ECDSAOutcalls, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::HTTPOutcalls, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::SchnorrOutcalls, CanisterCyclesCostSchedule::Free)
            | (CyclesUseCase::VetKd, CanisterCyclesCostSchedule::Free) => Cycles::zero(),
        };
        Self {
            real: amount,
            nominal: NominalCycles::new_private(amount.get()),
            _cycles_use_case_marker: PhantomData,
        }
    }

    pub fn real(&self) -> Cycles {
        self.real
    }

    pub fn nominal(&self) -> NominalCycles {
        self.nominal
    }
}

impl<T: CyclesUseCaseKind> Add for CompoundCycles<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            real: self.real + rhs.real,
            nominal: self.nominal + rhs.nominal,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}

impl<T: CyclesUseCaseKind> AddAssign for CompoundCycles<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.real = self.real + rhs.real;
        self.nominal = self.nominal + rhs.nominal;
    }
}

impl<T: CyclesUseCaseKind> Sub for CompoundCycles<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            real: self.real - rhs.real,
            nominal: self.nominal - rhs.nominal,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}

impl<T: CyclesUseCaseKind> SubAssign for CompoundCycles<T> {
    fn sub_assign(&mut self, rhs: Self) {
        self.real = self.real - rhs.real;
        self.nominal = self.nominal - rhs.nominal;
    }
}

impl<T: CyclesUseCaseKind> Mul<u64> for CompoundCycles<T> {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        Self {
            real: self.real * rhs,
            nominal: self.nominal * rhs,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}

impl<T: CyclesUseCaseKind> Div<u128> for CompoundCycles<T> {
    type Output = Self;

    fn div(self, rhs: u128) -> Self {
        Self {
            real: self.real / rhs,
            nominal: self.nominal / rhs,
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }
}
