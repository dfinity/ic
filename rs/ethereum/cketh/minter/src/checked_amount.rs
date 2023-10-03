#[cfg(test)]
mod tests;

use minicbor;
use rlp::RlpStream;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;
use std::num::ParseIntError;
use std::ops::Rem;

/// `CheckedAmountOf<Unit>` provides a type-safe way to keep an amount of some `Unit`.
/// In contrast to `AmountOf<Unit>`, all operations are checked and do not overflow.
///
/// # Arithmetic
/// ```
/// use ic_cketh_minter::checked_amount::CheckedAmountOf;
///
/// enum MetricApple{}
/// type Apples = CheckedAmountOf<MetricApple>;
/// let three_apples = Apples::from(3_u8);
///
/// //Checked addition
/// assert_eq!(three_apples.checked_add(Apples::TWO), Some(Apples::from(5_u8)));
/// assert_eq!(Apples::MAX.checked_add(Apples::ONE), None);
///
/// //Checked subtraction
/// assert_eq!(three_apples.checked_sub(Apples::TWO), Some(Apples::ONE));
/// assert_eq!(Apples::TWO.checked_sub(three_apples), None);
///
/// //Checked multiplication by scalar
/// assert_eq!(three_apples.checked_mul(2_u8), Some(Apples::from(6_u8)));
/// assert_eq!(Apples::MAX.checked_mul(2_u8), None);
///
/// // Ceiling checked division by scalar
/// assert_eq!(three_apples.checked_div_ceil(0_u8), None);
/// assert_eq!(three_apples.checked_div_ceil(2_u8), Some(Apples::TWO));
/// ```
pub struct CheckedAmountOf<Unit>(ethnum::u256, PhantomData<Unit>);

impl<Unit> CheckedAmountOf<Unit> {
    pub const ZERO: Self = Self(ethnum::u256::ZERO, PhantomData);
    pub const ONE: Self = Self(ethnum::u256::ONE, PhantomData);
    pub const TWO: Self = Self(ethnum::u256::new(2), PhantomData);
    pub const MAX: Self = Self(ethnum::u256::MAX, PhantomData);

    /// `new` is a synonym for `from` that can be evaluated in
    /// compile time. The main use-case of this functions is defining
    /// constants.
    #[inline]
    pub const fn new(value: u128) -> CheckedAmountOf<Unit> {
        Self(ethnum::u256::new(value), PhantomData)
    }

    #[inline]
    const fn from_inner(value: ethnum::u256) -> Self {
        Self(value, PhantomData)
    }

    #[inline]
    pub const fn from_words(hi: u128, lo: u128) -> Self {
        Self::from_inner(ethnum::u256::from_words(hi, lo))
    }

    pub fn from_str_hex(src: &str) -> Result<Self, ParseIntError> {
        ethnum::u256::from_str_hex(src).map(Self::from_inner)
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self::from_inner(ethnum::u256::from_be_bytes(bytes))
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self::from_inner)
    }

    pub fn checked_increment(&self) -> Option<Self> {
        self.checked_add(Self::ONE)
    }

    pub fn checked_decrement(&self) -> Option<Self> {
        self.checked_sub(Self::ONE)
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self::from_inner)
    }

    pub fn checked_mul<T: Into<ethnum::u256>>(self, other: T) -> Option<Self> {
        self.0
            .checked_mul(other.into())
            .map(|res| Self(res, PhantomData))
    }

    pub fn checked_div_ceil<T: Into<ethnum::u256>>(self, rhs: T) -> Option<Self> {
        let rhs = rhs.into();
        if rhs == ethnum::u256::ZERO {
            return None;
        }
        let (quotient, remainder) = (self.0.div_euclid(rhs), self.0.rem(&rhs));
        if remainder == ethnum::u256::ZERO {
            Some(Self::from_inner(quotient))
        } else {
            Self::from_inner(quotient).checked_increment()
        }
    }

    pub fn as_f64(&self) -> f64 {
        self.0.as_f64()
    }

    /// Returns the display implementation of the inner value.
    /// Useful to avoid thousands separators if value is used for example in URLs.
    /// ```
    /// use ic_cketh_minter::checked_amount::CheckedAmountOf;
    ///
    /// enum MetricApple{}
    /// type Apples = CheckedAmountOf<MetricApple>;
    /// let many_apples = Apples::from(4_332_415_u32);
    ///
    /// assert_eq!(many_apples.to_string_inner(), "4332415".to_string());
    /// ```
    pub fn to_string_inner(&self) -> String {
        self.0.to_string()
    }
}

macro_rules! impl_from {
    ($($t:ty),* $(,)?) => {$(
        impl<Unit> From<$t> for CheckedAmountOf<Unit> {
            #[inline]
            fn from(value: $t) -> Self {
                Self(ethnum::u256::from(value), PhantomData)
            }
        }
    )*};
}

impl_from! { u8, u16, u32, u64, u128 }

impl<Unit> TryFrom<candid::Nat> for CheckedAmountOf<Unit> {
    type Error = String;

    fn try_from(value: candid::Nat) -> Result<Self, Self::Error> {
        let value_bytes = value.0.to_bytes_be();
        let mut value_u256 = [0u8; 32];
        if value_bytes.len() <= 32 {
            value_u256[32 - value_bytes.len()..].copy_from_slice(&value_bytes);
        } else {
            return Err(format!("Nat does not fit in a U256: {}", value));
        }
        Ok(Self::from_inner(ethnum::u256::from_be_bytes(value_u256)))
    }
}

impl<Unit> From<CheckedAmountOf<Unit>> for candid::Nat {
    fn from(value: CheckedAmountOf<Unit>) -> Self {
        use num_bigint::BigUint;
        candid::Nat::from(BigUint::from_bytes_be(&value.0.to_be_bytes()))
    }
}

impl<Unit> fmt::Debug for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use thousands::Separable;
        write!(f, "{}", self.0.separate_with_underscores())
    }
}

impl<Unit> fmt::Display for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use thousands::Separable;
        write!(f, "{}", self.0.separate_with_underscores())
    }
}

impl<Unit> fmt::LowerHex for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<Unit> fmt::UpperHex for CheckedAmountOf<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl<Unit> Clone for CheckedAmountOf<Unit> {
    fn clone(&self) -> Self {
        CheckedAmountOf(self.0, PhantomData)
    }
}

impl<Unit> Copy for CheckedAmountOf<Unit> {}

impl<Unit> PartialEq for CheckedAmountOf<Unit> {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}

impl<Unit> Eq for CheckedAmountOf<Unit> {}

impl<Unit> PartialOrd for CheckedAmountOf<Unit> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&rhs.0)
    }
}

impl<Unit> Ord for CheckedAmountOf<Unit> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.0.cmp(&rhs.0)
    }
}

// Derived serde `impl Serialize` produces an extra `unit` value for
// phantom data, e.g. `AmountOf::<Meters>::from(10)` is serialized
// into json as `[10, null]` by default.
//
// We want serialization format of `Repr` and the `AmountOf` to match
// exactly, that's why we have to provide custom instances.
impl<Unit> Serialize for CheckedAmountOf<Unit> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, Unit> Deserialize<'de> for CheckedAmountOf<Unit> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ethnum::u256::deserialize(deserializer).map(Self::from_inner)
    }
}

impl<C, Unit> minicbor::Encode<C> for CheckedAmountOf<Unit> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        crate::cbor::u256::encode(&self.0, e, ctx)
    }
}

impl<'b, C, Unit> minicbor::Decode<'b, C> for CheckedAmountOf<Unit> {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        crate::cbor::u256::decode(d, ctx).map(Self::from_inner)
    }
}

impl<Unit> rlp::Encodable for CheckedAmountOf<Unit> {
    fn rlp_append(&self, s: &mut RlpStream) {
        let leading_empty_bytes: usize = self.0.leading_zeros() as usize / 8;
        s.append(&self.0.to_be_bytes()[leading_empty_bytes..].as_ref());
    }
}
