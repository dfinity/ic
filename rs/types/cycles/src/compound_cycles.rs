use crate::{
    cycles::Cycles,
    cycles_cost_schedule::CanisterCyclesCostSchedule,
    cycles_use_case::{CyclesUseCase, CyclesUseCaseKind},
    nominal_cycles::NominalCycles,
};
use ic_protobuf::{proxy::ProxyDecodeError, state::queues::v1::CompoundCycles as PbCompoundCycles};
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
/// created for the same `CyclesUseCase`. The `CanisterCyclesCostSchedule` is not
/// part of the type: `new` folds it into the real part and does not retain it, so
/// nothing stops two amounts created under different cost schedules from being
/// combined (see the note on ordering below).
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
///
/// # No ordering
///
/// `CompoundCycles` deliberately implements neither `Ord` nor `PartialOrd`: its two
/// parts are accounted for independently and there is no meaningful order on the
/// pair. A derived impl would order lexicographically, i.e. by the real part first,
/// and hence decide a comparison on the real parts alone whenever those differ, no
/// matter how the nominal parts compare.
///
/// Two amounts carrying the same cost schedule are safe to compare that way: under
/// the normal cost schedule the two parts of an amount coincide, and under the free
/// cost schedule the real part of a use case made free is zero on both sides, so the
/// comparison falls through to the nominal parts. Such an order is misleading
/// precisely when the two amounts carry *different* cost schedules, e.g. because one
/// was recorded when a call was performed and the other derived when its response is
/// executed: the one made free has a zero real part and compares as the smaller
/// amount however large its nominal part is.
///
/// Compare `real()` or `nominal()` explicitly instead, or use `component_wise_min`
/// to bound both parts at once. Note also that subtraction saturates part by part,
/// so capping an amount before subtracting it is redundant: `x - y` already equals
/// `x - x.component_wise_min(y)`.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct CompoundCycles<T: CyclesUseCaseKind> {
    real: Cycles,
    nominal: NominalCycles,
    _cycles_use_case_marker: PhantomData<T>,
}

impl<T: CyclesUseCaseKind> CompoundCycles<T> {
    pub fn new(amount: Cycles, cost_schedule: CanisterCyclesCostSchedule) -> Self {
        let use_case = T::cycles_use_case();
        let nominal = NominalCycles::new_private(amount.get());
        let real = match (use_case, cost_schedule) {
            (_, CanisterCyclesCostSchedule::Normal)
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
            real,
            nominal,
            _cycles_use_case_marker: PhantomData,
        }
    }

    pub fn real(&self) -> Cycles {
        self.real
    }

    pub fn nominal(&self) -> NominalCycles {
        self.nominal
    }

    // Returns true if both the real and nominal parts of this `CompoundCycles`
    // are zero.
    pub fn is_zero(&self) -> bool {
        self.real.is_zero() && self.nominal.is_zero()
    }

    /// Returns the component-wise minimum of this amount and `other`, i.e. the
    /// minimum of their real parts paired with the minimum of their nominal parts.
    ///
    /// The two components are minimized separately because there is no ordering on
    /// the pair (see the note on this type). They coincide under the normal cost
    /// schedule; under the free cost schedule the real part of a use case made free
    /// is zero, so minimizing by the real parts alone would leave the nominal part
    /// of the result unbounded.
    pub fn component_wise_min(self, other: Self) -> Self {
        Self {
            real: self.real.min(other.real),
            nominal: self.nominal.min(other.nominal),
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
    }

    /// Returns this amount reduced by the part of `real()` that could not be
    /// charged, e.g. because the balance it was to be subtracted from did not
    /// cover it. Such an amount is never removed from any balance, so it must
    /// not be reported in the consumed cycles metrics either.
    ///
    /// Both parts are reduced by `uncharged`, saturating at zero: they coincide
    /// under the normal cost schedule. Under the free cost schedule the real part
    /// is zero for use cases made free, so this is a no-op; use cases charged
    /// regardless of schedule still have coincident real and nominal parts.
    pub fn minus_uncharged(self, uncharged: Cycles) -> Self {
        debug_assert!(
            uncharged <= self.real,
            "Expected the uncharged amount {uncharged} to be at most the real amount {}",
            self.real
        );
        Self {
            real: self.real - uncharged,
            nominal: self.nominal - NominalCycles::new_private(uncharged.get()),
            _cycles_use_case_marker: self._cycles_use_case_marker,
        }
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

impl<T: CyclesUseCaseKind> From<CompoundCycles<T>> for PbCompoundCycles {
    fn from(item: CompoundCycles<T>) -> Self {
        Self {
            real: Some(item.real().into()),
            nominal: Some((&item.nominal()).into()),
        }
    }
}

impl<T: CyclesUseCaseKind> TryFrom<PbCompoundCycles> for CompoundCycles<T> {
    type Error = ProxyDecodeError;

    fn try_from(compound_cycles: PbCompoundCycles) -> Result<Self, Self::Error> {
        let real = compound_cycles
            .real
            .ok_or(ProxyDecodeError::MissingField("CompoundCycles::real"))?;
        let nominal = NominalCycles::try_from(
            compound_cycles
                .nominal
                .ok_or(ProxyDecodeError::MissingField("CompoundCycles::nominal"))?,
        )?;
        Ok(CompoundCycles {
            real: Cycles::try_from(real)?,
            nominal,
            _cycles_use_case_marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cycles_use_case::Instructions;
    use crate::nominal_cycles::testing::NominalCyclesTesting;

    /// An `Instructions` amount has coincident parts under the normal cost schedule,
    /// whereas its real part is zero under the free cost schedule. The two amounts
    /// below therefore order one way in their real parts and the other way in their
    /// nominal parts, which is exactly the case a lexicographic ordering of the pair
    /// would decide on the real parts alone.
    #[test]
    fn arithmetic_is_component_wise() {
        let x =
            CompoundCycles::<Instructions>::new(Cycles::new(5), CanisterCyclesCostSchedule::Normal);
        let y =
            CompoundCycles::<Instructions>::new(Cycles::new(10), CanisterCyclesCostSchedule::Free);
        assert_eq!(
            (x.real(), x.nominal()),
            (Cycles::new(5), NominalCycles::new(5))
        );
        assert_eq!(
            (y.real(), y.nominal()),
            (Cycles::zero(), NominalCycles::new(10))
        );

        // Subtracting `y` from `x` without going below zero, part by part.
        let difference = x - y;
        assert_eq!(
            (difference.real(), difference.nominal()),
            (Cycles::new(5), NominalCycles::zero())
        );

        // The component-wise minimum takes each part from a different amount.
        let minimum = x.component_wise_min(y);
        assert_eq!(
            (minimum.real(), minimum.nominal()),
            (Cycles::zero(), NominalCycles::new(5))
        );
        assert_eq!(y.component_wise_min(x), minimum);

        // Capping before subtracting is redundant.
        assert_eq!(x - x.component_wise_min(y), difference);
    }
}
