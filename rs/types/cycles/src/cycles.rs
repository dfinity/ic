use candid::{CandidType, Nat};
use ic_heap_bytes::DeterministicHeapBytes;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::canister_state_bits::v1::CyclesAccount as pbCyclesAccount;
use ic_protobuf::state::queues::v1::Cycles as PbCycles;
use ic_utils_thousands::separate_with_underscores;
use serde::{Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::iter::Sum;
use std::{
    fmt,
    ops::{Add, AddAssign, Div, Mul, Sub, SubAssign},
};

/// Struct to be used for updates to the canister's balance. They are maintained as a
/// simple u128. We implement our own arithmetic functions on them so that we
/// can ensure that they never overflow or underflow.
///
/// NOTE: This is distinct from `NominalCycles` which should be used to update metrics
/// related to cycles accounting.
///
/// NOTE: The derived `Serialize` impl is transparent, i.e. it emits the inner
/// `u128`. CBOR (see `serde_cbor`) cannot represent integers above `u64::MAX`,
/// so serializing a `Cycles` larger than that with `serde_cbor` *fails*. Types
/// that hold a `Cycles` and are CBOR-encoded must therefore annotate the field
/// with `#[serde(with = "ic_types_cycles::serde_as_u64_pair")]`, which encodes
/// the full `u128` range as a pair of `u64`s.
#[derive(
    Copy,
    Clone,
    Eq,
    DeterministicHeapBytes,
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
pub struct Cycles(u128);

impl Cycles {
    pub const fn new(input: u128) -> Self {
        Self(input)
    }

    pub const fn from_parts(high: u64, low: u64) -> Self {
        Self(((high as u128) << 64) | low as u128)
    }

    pub const fn zero() -> Self {
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

    /// Divides by `rhs`, rounding up, i.e. the smallest amount of cycles such that
    /// `rhs` of them cover `self`. The `Div` impls truncate instead.
    ///
    /// # Panics
    ///
    /// Panics if `rhs` is zero.
    pub fn div_ceil(self, rhs: u128) -> Self {
        Self(self.0.div_ceil(rhs))
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

/// Decodes `Cycles` from their little-endian representation, as produced by
/// `From<Cycles> for Vec<u8>`. Fails if `bytes` is not exactly 16 bytes long.
///
/// Takes a `&Vec<u8>` rather than a `&[u8]` because that is what all callers
/// hold, and a `&[u8]` impl alone would force each of them to spell out an
/// `as_slice()`. A blanket `impl<T: AsRef<[u8]>>` covering both is not
/// possible: it would conflict with the `impl<T, U: Into<T>> TryFrom<U> for T`
/// in `core`.
impl TryFrom<&Vec<u8>> for Cycles {
    type Error = TryFromSliceError;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self::new(u128::from_le_bytes(bytes.as_slice().try_into()?)))
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
        write!(f, "{}", separate_with_underscores(self.0))
    }
}

impl From<Cycles> for PbCycles {
    fn from(item: Cycles) -> Self {
        Self {
            raw_cycles: item.into(),
        }
    }
}

impl TryFrom<PbCycles> for Cycles {
    type Error = ProxyDecodeError;

    fn try_from(item: PbCycles) -> Result<Self, Self::Error> {
        try_from_le_bytes(item.raw_cycles)
    }
}

impl From<Cycles> for pbCyclesAccount {
    fn from(item: Cycles) -> Self {
        Self {
            cycles_balance: item.into(),
        }
    }
}

impl TryFrom<pbCyclesAccount> for Cycles {
    type Error = ProxyDecodeError;

    fn try_from(value: pbCyclesAccount) -> Result<Self, Self::Error> {
        try_from_le_bytes(value.cycles_balance)
    }
}

/// Serializes [`Cycles`] as a `(high, low)` pair of `u64`s instead of as a bare
/// `u128`, for use with `#[serde(with = "...")]`.
///
/// The derived, transparent `Serialize` impl emits a `u128`, which CBOR cannot
/// represent beyond `u64::MAX`: `serde_cbor` fails with "The number can't be
/// stored in CBOR". Any type holding a `Cycles` that is CBOR-encoded must use
/// this module.
pub mod serde_as_u64_pair {
    use super::Cycles;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(cycles: &Cycles, serializer: S) -> Result<S::Ok, S::Error> {
        cycles.into_parts().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Cycles, D::Error> {
        let (high, low) = <(u64, u64)>::deserialize(deserializer)?;
        Ok(Cycles::from_parts(high, low))
    }
}

/// Decodes `Cycles` from the little-endian representation used by the protobuf
/// encodings above, mapping a length mismatch onto a `ProxyDecodeError`.
fn try_from_le_bytes(bytes: Vec<u8>) -> Result<Cycles, ProxyDecodeError> {
    Cycles::try_from(&bytes).map_err(|_| ProxyDecodeError::ValueOutOfRange {
        typ: "Cycles",
        err: format!("expected 16 bytes, got {}", bytes.len()),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::BTreeSet;

    /// Holds a `Cycles` encoded via [`serde_as_u64_pair`].
    #[derive(Debug, PartialEq, Deserialize, Serialize)]
    struct AsU64Pair(#[serde(with = "serde_as_u64_pair")] Cycles);

    /// A handful of amounts either side of the `u64::MAX` boundary.
    const AMOUNTS: [Cycles; 5] = [
        Cycles::zero(),
        Cycles::new(1),
        Cycles::new(u64::MAX as u128),
        Cycles::new(u64::MAX as u128 + 1),
        Cycles::new(u128::MAX),
    ];

    /// The derived `Serialize` impl is transparent, i.e. it emits the inner
    /// `u128`, and CBOR cannot represent integers above `u64::MAX`.
    #[test]
    fn cbor_cannot_encode_large_cycles_transparently() {
        assert!(serde_cbor::to_vec(&Cycles::new(u64::MAX as u128)).is_ok());
        assert!(serde_cbor::to_vec(&Cycles::new(u64::MAX as u128 + 1)).is_err());
        assert!(serde_cbor::to_vec(&Cycles::new(u128::MAX)).is_err());
    }

    /// [`serde_as_u64_pair`] must round-trip the whole `Cycles` range through
    /// CBOR. That is what makes it usable in CBOR-encoded signed bytes.
    #[test]
    fn serde_as_u64_pair_round_trips_through_cbor() {
        for amount in AMOUNTS {
            let bytes = serde_cbor::to_vec(&AsU64Pair(amount))
                .unwrap_or_else(|err| panic!("failed to encode {amount}: {err}"));
            let decoded: AsU64Pair = serde_cbor::from_slice(&bytes)
                .unwrap_or_else(|err| panic!("failed to decode {amount}: {err}"));
            assert_eq!(AsU64Pair(amount), decoded);
        }
    }

    /// Distinct amounts must have distinct encodings: types signing over a
    /// `Cycles` rely on [`serde_as_u64_pair`] to produce unambiguous bytes.
    #[test]
    fn serde_as_u64_pair_encodings_are_distinct() {
        let encodings: BTreeSet<_> = AMOUNTS
            .iter()
            .map(|amount| serde_cbor::to_vec(&AsU64Pair(*amount)).unwrap())
            .collect();
        assert_eq!(encodings.len(), AMOUNTS.len());
    }

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
    fn test_div_ceil() {
        assert_eq!(Cycles::zero().div_ceil(u128::MAX), Cycles::zero());
        assert_eq!(Cycles::from(u128::MAX).div_ceil(1), Cycles::from(u128::MAX));
        // Anything but an exact multiple of the divisor is rounded up, so that the
        // divisor covers the dividend rather than falling a cycle short.
        assert_eq!(Cycles::from(9_u128).div_ceil(3), Cycles::from(3_u128));
        assert_eq!(Cycles::from(10_u128).div_ceil(3), Cycles::from(4_u128));
        assert_eq!(Cycles::from(12_u128).div_ceil(3), Cycles::from(4_u128));
        // Including a divisor larger than the dividend: a single cycle is the smallest
        // amount of which `rhs` cover a non-zero `self`.
        assert_eq!(Cycles::from(1_u128).div_ceil(3), Cycles::from(1_u128));
        assert_eq!(Cycles::from(u128::MAX).div_ceil(u128::MAX), Cycles::new(1));
        // Which is what tells it apart from the truncating `Div`.
        assert_eq!(Cycles::from(10_u128) / 3_u128, Cycles::from(3_u128));
        assert_eq!(Cycles::from(1_u128) / 3_u128, Cycles::zero());
    }

    #[test]
    #[should_panic(expected = "divide by zero")]
    fn test_div_ceil_by_zero_panics() {
        let _ = Cycles::from(1_u128).div_ceil(0);
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
            Cycles::from(u128::MAX) - Cycles::from(10_u128),
            Cycles::from(u128::MAX - 10)
        );
        assert_eq!(Cycles::zero() - Cycles::from(10_u128), Cycles::zero());
        assert_eq!(
            Cycles::from(10_u128) - Cycles::from(20_u128),
            Cycles::zero()
        );
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
        assert_eq!(format!("{cycles}"), "1_234_567_890");
        assert_eq!(format!("{cycles:?}"), "Cycles(1234567890)");
    }

    #[test]
    fn test_formatting_with_underscore_saparators_u128_max() {
        let cycles = Cycles::new(u128::MAX);
        assert_eq!(
            format!("{cycles}"),
            "340_282_366_920_938_463_463_374_607_431_768_211_455"
        );
        assert_eq!(
            format!("{cycles:?}"),
            "Cycles(340282366920938463463374607431768211455)"
        );
    }

    #[test]
    fn test_le_bytes_roundtrip() {
        for cycles in [Cycles::zero(), Cycles::new(1), Cycles::new(u128::MAX)] {
            let bytes: Vec<u8> = cycles.into();
            assert_eq!(bytes.len(), 16);
            assert_eq!(Cycles::try_from(&bytes).unwrap(), cycles);
        }
    }

    #[test]
    fn test_try_from_le_bytes_of_wrong_length_fails() {
        for len in [0, 15, 17] {
            assert!(Cycles::try_from(&vec![0; len]).is_err());
        }
    }

    #[test]
    fn test_try_from_proto_with_wrong_length_fails() {
        for len in [0, 15, 17] {
            let err = Cycles::try_from(PbCycles {
                raw_cycles: vec![0; len],
            })
            .unwrap_err();
            assert!(
                matches!(err, ProxyDecodeError::ValueOutOfRange { typ: "Cycles", .. }),
                "unexpected error: {err:?}"
            );

            let err = Cycles::try_from(pbCyclesAccount {
                cycles_balance: vec![0; len],
            })
            .unwrap_err();
            assert!(
                matches!(err, ProxyDecodeError::ValueOutOfRange { typ: "Cycles", .. }),
                "unexpected error: {err:?}"
            );
        }
    }
}
