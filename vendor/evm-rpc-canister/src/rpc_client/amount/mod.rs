use evm_rpc_types::Nat256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;

/// `Amount<Unit>` provides a type-safe way to keep an amount of some `Unit`.
pub struct Amount<Unit>(ethnum::u256, PhantomData<Unit>);

impl<Unit> Amount<Unit> {
    pub const ZERO: Self = Self(ethnum::u256::ZERO, PhantomData);
    pub const ONE: Self = Self(ethnum::u256::ONE, PhantomData);
    pub const TWO: Self = Self(ethnum::u256::new(2), PhantomData);
    pub const MAX: Self = Self(ethnum::u256::MAX, PhantomData);

    /// `new` is a synonym for `from` that can be evaluated in
    /// compile time. The main use-case of this functions is defining
    /// constants.
    #[inline]
    pub const fn new(value: u128) -> Amount<Unit> {
        Self(ethnum::u256::new(value), PhantomData)
    }

    #[inline]
    const fn from_inner(value: ethnum::u256) -> Self {
        Self(value, PhantomData)
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self::from_inner(ethnum::u256::from_be_bytes(bytes))
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Returns the display implementation of the inner value.
    /// Useful to avoid thousands of separators if value is used for example in URLs.
    /// ```
    /// use evm_rpc::rpc_client::amount::Amount;
    ///
    /// enum MetricApple{}
    /// type Apples = Amount<MetricApple>;
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
        impl<Unit> From<$t> for Amount<Unit> {
            #[inline]
            fn from(value: $t) -> Self {
                Self(ethnum::u256::from(value), PhantomData)
            }
        }
    )*};
}

impl_from! { u8, u16, u32, u64, u128 }

impl<Unit> From<Nat256> for Amount<Unit> {
    fn from(value: Nat256) -> Self {
        Self::from_be_bytes(value.into_be_bytes())
    }
}

impl<Unit> From<Amount<Unit>> for Nat256 {
    fn from(value: Amount<Unit>) -> Self {
        Nat256::from_be_bytes(value.to_be_bytes())
    }
}

impl<Unit> fmt::Debug for Amount<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use thousands::Separable;
        write!(f, "{}", self.0.separate_with_underscores())
    }
}

impl<Unit> fmt::Display for Amount<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use thousands::Separable;
        write!(f, "{}", self.0.separate_with_underscores())
    }
}

impl<Unit> fmt::LowerHex for Amount<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<Unit> fmt::UpperHex for Amount<Unit> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:X}", self.0)
    }
}

impl<Unit> Clone for Amount<Unit> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Unit> Copy for Amount<Unit> {}

impl<Unit> PartialEq for Amount<Unit> {
    fn eq(&self, rhs: &Self) -> bool {
        self.0.eq(&rhs.0)
    }
}

impl<Unit> Eq for Amount<Unit> {}

impl<Unit> PartialOrd for Amount<Unit> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl<Unit> Ord for Amount<Unit> {
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
impl<Unit> Serialize for Amount<Unit> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, Unit> Deserialize<'de> for Amount<Unit> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ethnum::u256::deserialize(deserializer).map(Self::from_inner)
    }
}
