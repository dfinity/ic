use candid::CandidType;
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

    pub fn get(self) -> u128 {
        self.0
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

impl Into<Vec<u8>> for Cycles {
    fn into(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Into<u64> for Cycles {
    fn into(self) -> u64 {
        self.0 as u64
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
}
