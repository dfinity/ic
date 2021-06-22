//! Cycles struct to be used for metrics collection.
use crate::Cycles;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    ops::{Add, AddAssign, Sub, SubAssign},
};

use std::convert::{From, TryFrom};

/// Struct to handle cycles that we want to track in metrics.
/// They are maintained as a simple u128. We implement our own arithmetic
/// functions on them so that we can ensure that they never overflow or
/// underflow. A similar struct is provided in the protobuf types.
/// We also provide split into low and high parts as protobuf does not support
/// u128.
//
// EXC-24 will introduce a separation of concepts between Cycles and NominalCycles.
#[derive(
    Clone, Copy, Default, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
pub struct NominalCycles(u128);

impl NominalCycles {
    pub fn new(input: u128) -> Self {
        Self(input)
    }

    pub fn from_cycles(input: Cycles) -> Self {
        Self(input.get() as u128)
    }

    pub fn from_parts(high: u64, low: u64) -> Self {
        Self((high as u128) << 64 | low as u128)
    }

    pub fn get(&self) -> u128 {
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
}

impl From<u128> for NominalCycles {
    fn from(input: u128) -> Self {
        Self::new(input)
    }
}

impl From<Cycles> for NominalCycles {
    fn from(input: Cycles) -> Self {
        Self::new(input.get())
    }
}

impl Add for NominalCycles {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for NominalCycles {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_add(rhs.0)
    }
}

impl Sub for NominalCycles {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl SubAssign for NominalCycles {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0.saturating_sub(rhs.0)
    }
}

impl fmt::Display for NominalCycles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&NominalCycles> for pb::NominalCycles {
    fn from(item: &NominalCycles) -> Self {
        Self {
            high: item.high64(),
            low: item.low64(),
        }
    }
}

impl TryFrom<pb::NominalCycles> for NominalCycles {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::NominalCycles) -> Result<Self, Self::Error> {
        Ok(NominalCycles::from_parts(value.high, value.low))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_parts() {
        let nom = NominalCycles::from_parts(6692605942, 14083847773837265618);
        assert_eq!(nom, NominalCycles::new(123456789012345678901234567890));

        assert_eq!(
            NominalCycles::from_parts(u64::MAX, u64::MAX),
            NominalCycles::from(u128::MAX)
        );
    }

    #[test]
    fn test_low64() {
        let nom = NominalCycles::new(123456789012345678901234567890);
        assert_eq!(nom.low64(), 14083847773837265618);

        assert_eq!(NominalCycles::new(u128::MAX).low64(), u64::MAX);
    }

    #[test]
    fn test_high64() {
        let nom = NominalCycles::new(123456789012345678901234567890);
        assert_eq!(nom.high64(), 6692605942);

        assert_eq!(NominalCycles::new(u128::MAX).high64(), u64::MAX);
    }

    #[test]
    fn test_into_parts() {
        let nom = NominalCycles::new(123456789012345678901234567890);
        assert_eq!(nom.into_parts(), (nom.high64(), nom.low64()))
    }
}
