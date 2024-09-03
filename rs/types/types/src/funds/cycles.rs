use candid::{CandidType, Nat};
#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::state::canister_state_bits::v1::CyclesAccount as pbCyclesAccount;
use ic_protobuf::state::queues::v1::Cycles as PbCycles;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::iter::Sum;
use std::{
    fmt,
    ops::{Add, AddAssign, Div, Mul, Sub, SubAssign},
};
use thousands::Separable;

/// Struct to handle cycles on the IC. They are maintained as a
/// simple u128. We implement our own arithmetic functions on them so that we
/// can ensure that they never overflow or underflow.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    Default,
    CandidType,
    Deserialize,
    Serialize,
)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct Cycles(u128);

impl Cycles {
    pub const fn new(input: u128) -> Self {
        Self(input)
    }

    pub fn from_parts(high: u64, low: u64) -> Self {
        Self((high as u128) << 64 | low as u128)
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn get(self) -> u128 {
        self.0
    }

    pub fn into_parts(self) -> (u64, u64) {
        (self.high64(), self.low64())
    }

    pub fn high64(&self) -> u64 {
        (self.0 >> 64) as u64
    }

    pub fn low64(&self) -> u64 {
        (self.0 & 0xffff_ffff_ffff_ffff) as u64
    }

    pub fn take(&mut self) -> Cycles {
        let amount = self.0;
        self.0 = 0;
        Cycles(amount)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Checked multiplication. Computes `self * rhs`, returning `None`
    /// if overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<Self> {
        self.0.checked_mul(rhs as u128).map(Cycles::from)
    }
}

impl From<u128> for Cycles {
    fn from(input: u128) -> Self {
        Self::new(input)
    }
}

impl From<u64> for Cycles {
    fn from(input: u64) -> Self {
        Self::new(input as u128)
    }
}

impl From<&Vec<u8>> for Cycles {
    fn from(bytes: &Vec<u8>) -> Self {
        Self::new(u128::from_le_bytes(bytes.as_slice().try_into().unwrap()))
    }
}

impl From<Cycles> for Vec<u8> {
    fn from(val: Cycles) -> Self {
        val.0.to_le_bytes().to_vec()
    }
}

impl From<Cycles> for u128 {
    fn from(val: Cycles) -> Self {
        val.0
    }
}

impl From<Cycles> for Nat {
    fn from(val: Cycles) -> Self {
        val.0.into()
    }
}

impl Add for Cycles {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for Cycles {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_add(rhs.0)
    }
}

impl Sub for Cycles {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl SubAssign for Cycles {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_sub(rhs.0)
    }
}

impl Mul<u64> for Cycles {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        Self(self.0.saturating_mul(Cycles::from(rhs).0))
    }
}

impl Mul<u128> for Cycles {
    type Output = Self;

    fn mul(self, rhs: u128) -> Self {
        Self(self.0.saturating_mul(Cycles::from(rhs).0))
    }
}

impl Mul<usize> for Cycles {
    type Output = Self;

    fn mul(self, rhs: usize) -> Self {
        Self(self.0.saturating_mul(Cycles::from(rhs as u128).0))
    }
}

impl Div<u64> for Cycles {
    type Output = Self;

    fn div(self, rhs: u64) -> Self {
        Self(self.0.saturating_div(Cycles::from(rhs).0))
    }
}

impl Div<u128> for Cycles {
    type Output = Self;

    fn div(self, rhs: u128) -> Self {
        Self(self.0.saturating_div(Cycles::from(rhs).0))
    }
}

impl Div<usize> for Cycles {
    type Output = Self;

    fn div(self, rhs: usize) -> Self {
        Self(self.0.saturating_div(Cycles::from(rhs as u128).0))
    }
}

impl Sum for Cycles {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Cycles::zero(), Cycles::add)
    }
}

impl fmt::Display for Cycles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.separate_with_underscores())
    }
}

impl From<Cycles> for PbCycles {
    fn from(item: Cycles) -> Self {
        Self {
            raw_cycles: item.into(),
        }
    }
}

impl From<PbCycles> for Cycles {
    fn from(item: PbCycles) -> Self {
        Self::from(&item.raw_cycles)
    }
}

impl From<Cycles> for pbCyclesAccount {
    fn from(item: Cycles) -> Self {
        Self {
            cycles_balance: item.into(),
        }
    }
}

impl From<pbCyclesAccount> for Cycles {
    fn from(value: pbCyclesAccount) -> Self {
        Self::from(&value.cycles_balance)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_addition() {
        assert_eq!(Cycles::zero() + Cycles::zero(), Cycles::zero());
        assert_eq!(
            Cycles::zero() + Cycles::from(u128::MAX),
            Cycles::from(u128::MAX)
        );
        assert_eq!(
            Cycles::from(u128::MAX) + Cycles::from(u128::MAX),
            Cycles::from(u128::MAX)
        );
        assert_eq!(
            Cycles::from(u128::MAX) + Cycles::from(10_u128),
            Cycles::from(u128::MAX)
        );
    }

    #[test]
    fn test_multiplication_u64() {
        assert_eq!(Cycles::zero() * u64::MAX, Cycles::zero());
        assert_eq!(Cycles::from(u128::MAX) * u64::MAX, Cycles::from(u128::MAX));
        assert_eq!(Cycles::from(u128::MAX) * 10_u64, Cycles::from(u128::MAX));
    }

    #[test]
    fn test_checked_mul() {
        assert_eq!(Cycles::zero().checked_mul(u64::MAX), Some(Cycles::zero()));
        assert_eq!(Cycles::from(u128::MAX).checked_mul(u64::MAX), None);
        assert_eq!(Cycles::from(u128::MAX).checked_mul(10_u64), None);
    }

    #[test]
    fn test_multiplication_u128() {
        assert_eq!(Cycles::zero() * u128::MAX, Cycles::zero());
        assert_eq!(Cycles::from(u128::MAX) * u128::MAX, Cycles::from(u128::MAX));
        assert_eq!(Cycles::from(u128::MAX) * 10_u128, Cycles::from(u128::MAX));
    }

    #[test]
    fn test_multiplication_usize() {
        assert_eq!(Cycles::zero() * usize::MAX, Cycles::zero());
        assert_eq!(
            Cycles::from(u128::MAX) * usize::MAX,
            Cycles::from(u128::MAX)
        );
        assert_eq!(Cycles::from(u128::MAX) * 10_usize, Cycles::from(u128::MAX));
    }

    #[test]
    fn test_division_u64() {
        assert_eq!(Cycles::zero() / u64::MAX, Cycles::zero());
        assert_eq!(Cycles::from(u128::MAX) / 1_u64, Cycles::from(u128::MAX));
    }

    #[test]
    fn test_division_u128() {
        assert_eq!(Cycles::zero() / u128::MAX, Cycles::zero());
        assert_eq!(Cycles::from(u128::MAX) / 1_u128, Cycles::from(u128::MAX));
    }

    #[test]
    fn test_division_usize() {
        assert_eq!(Cycles::zero() / usize::MAX, Cycles::zero());
        assert_eq!(Cycles::from(u128::MAX) / 1_usize, Cycles::from(u128::MAX));
    }

    #[test]
    fn test_subtraction() {
        assert_eq!(Cycles::zero() - Cycles::zero(), Cycles::zero());
        assert_eq!(Cycles::zero() - Cycles::from(u128::MAX), Cycles::zero());
        assert_eq!(
            Cycles::from(u128::MAX) - Cycles::from(u128::MAX),
            Cycles::zero()
        );
        assert_eq!(
            Cycles::from(u128::MAX) - Cycles::from(10u128),
            Cycles::from(u128::MAX - 10)
        );
        assert_eq!(Cycles::zero() - Cycles::from(10u128), Cycles::zero());
        assert_eq!(Cycles::from(10u128) - Cycles::from(20u128), Cycles::zero());
    }

    #[test]
    fn test_from_parts() {
        let nom = Cycles::from_parts(6692605942, 14083847773837265618);
        assert_eq!(nom, Cycles::new(123456789012345678901234567890));

        assert_eq!(
            Cycles::from_parts(u64::MAX, u64::MAX),
            Cycles::from(u128::MAX)
        );
    }

    #[test]
    fn test_low64() {
        let nom = Cycles::new(123456789012345678901234567890);
        assert_eq!(nom.low64(), 14083847773837265618);

        assert_eq!(Cycles::new(u128::MAX).low64(), u64::MAX);
    }

    #[test]
    fn test_high64() {
        let nom = Cycles::new(123456789012345678901234567890);
        assert_eq!(nom.high64(), 6692605942);

        assert_eq!(Cycles::new(u128::MAX).high64(), u64::MAX);
    }

    #[test]
    fn test_into_parts() {
        let nom = Cycles::new(123456789012345678901234567890);
        assert_eq!(nom.into_parts(), (nom.high64(), nom.low64()))
    }

    #[test]
    fn test_formatting_with_underscore_saparators_small_number() {
        let cycles = Cycles::new(1_234_567_890);
        assert_eq!(format!("{}", cycles), "1_234_567_890");
        assert_eq!(format!("{:?}", cycles), "Cycles(1234567890)");
    }

    #[test]
    fn test_formatting_with_underscore_saparators_u128_max() {
        let cycles = Cycles::new(u128::MAX);
        assert_eq!(
            format!("{}", cycles),
            "340_282_366_920_938_463_463_374_607_431_768_211_455"
        );
        assert_eq!(
            format!("{:?}", cycles),
            "Cycles(340282366920938463463374607431768211455)"
        );
    }
}
