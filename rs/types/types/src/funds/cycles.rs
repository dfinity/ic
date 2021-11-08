use candid::CandidType;
use ic_protobuf::state::canister_state_bits::v1::CyclesAccount as pbCyclesAccount;
use ic_protobuf::state::queues::v1::Cycles as PbCycles;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::{
    fmt,
    ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign},
};

/// Struct to handle cycles on the IC. They are maintained as a
/// simple u128. We implement our own arithmetic functions on them so that we
/// can ensure that they never overflow or underflow.
#[derive(
    Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize, CandidType,
)]
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

impl From<i32> for Cycles {
    fn from(input: i32) -> Self {
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

impl From<Cycles> for u64 {
    fn from(val: Cycles) -> Self {
        val.0 as u64
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

impl Mul for Cycles {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        Self(self.0.saturating_mul(rhs.0))
    }
}

impl Mul<u64> for Cycles {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        Self(self.0.saturating_mul(Cycles::from(rhs).0))
    }
}

impl Mul<i32> for Cycles {
    type Output = Self;

    fn mul(self, rhs: i32) -> Self {
        Self(self.0.saturating_mul(Cycles::from(rhs).0))
    }
}

impl Mul<usize> for Cycles {
    type Output = Self;

    fn mul(self, rhs: usize) -> Self {
        Self(self.0.saturating_mul(Cycles::from(rhs as u128).0))
    }
}

impl MulAssign for Cycles {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_mul(rhs.0)
    }
}

impl fmt::Display for Cycles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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
        assert_eq!(Cycles::from(0) + Cycles::from(0), Cycles::from(0));
        assert_eq!(
            Cycles::from(0) + Cycles::from(std::u128::MAX),
            Cycles::from(std::u128::MAX)
        );
        assert_eq!(
            Cycles::from(std::u128::MAX) + Cycles::from(std::u128::MAX),
            Cycles::from(std::u128::MAX)
        );
        assert_eq!(
            Cycles::from(std::u128::MAX) + Cycles::from(10),
            Cycles::from(std::u128::MAX)
        );
    }

    #[test]
    fn test_multiplication() {
        assert_eq!(Cycles::from(0) * Cycles::from(0), Cycles::from(0));
        assert_eq!(
            Cycles::from(0) * Cycles::from(std::u128::MAX),
            Cycles::from(0)
        );
        assert_eq!(
            Cycles::from(std::u128::MAX) * Cycles::from(std::u128::MAX),
            Cycles::from(std::u128::MAX)
        );
        assert_eq!(
            Cycles::from(std::u128::MAX) * Cycles::from(10),
            Cycles::from(std::u128::MAX)
        );
    }

    #[test]
    fn test_subtraction() {
        assert_eq!(Cycles::from(0) - Cycles::from(0), Cycles::from(0));
        assert_eq!(
            Cycles::from(0) - Cycles::from(std::u128::MAX),
            Cycles::from(0)
        );
        assert_eq!(
            Cycles::from(std::u128::MAX) - Cycles::from(std::u128::MAX),
            Cycles::from(0)
        );
        assert_eq!(
            Cycles::from(std::u128::MAX) - Cycles::from(10),
            Cycles::from(std::u128::MAX - 10)
        );
        assert_eq!(Cycles::from(0) - Cycles::from(10), Cycles::from(0));
        assert_eq!(Cycles::from(10) - Cycles::from(20), Cycles::from(0));
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
}
