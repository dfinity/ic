use candid::Nat;
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub, Zero};
use ic_stable_structures::storable::{Bound, Storable};
use num_traits::{Bounded, ToPrimitive};
use serde::{de::Deserializer, Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Serialize)]
#[serde(transparent)]
pub struct U64(u64);

impl U64 {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    #[inline]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    #[inline]
    pub fn to_u64(self) -> u64 {
        self.0
    }
}

impl FromStr for U64 {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(U64(s.parse().map_err(|_| {
            format!("Could not parse string to u64: {}", s)
        })?))
    }
}

impl fmt::Display for U64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<u64> for U64 {
    fn from(n: u64) -> Self {
        Self::new(n)
    }
}

impl From<U64> for Nat {
    fn from(n: U64) -> Self {
        Nat::from(n.0)
    }
}

impl TryFrom<Nat> for U64 {
    type Error = String;

    fn try_from(n: Nat) -> Result<Self, Self::Error> {
        Ok(Self(n.0.to_u64().ok_or_else(|| {
            format!("amount {} does not fit into u64 token type", n)
        })?))
    }
}

impl Storable for U64 {
    fn to_bytes(&self) -> Cow<[u8]> {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        Self(u64::from_bytes(bytes))
    }

    const BOUND: Bound = <u64 as Storable>::BOUND;
}

impl Bounded for U64 {
    fn min_value() -> Self {
        Self::ZERO
    }

    fn max_value() -> Self {
        Self::MAX
    }
}

impl CheckedAdd for U64 {
    fn checked_add(&self, other: &Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }
}

impl CheckedSub for U64 {
    fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

impl Zero for U64 {
    fn zero() -> Self {
        Self::ZERO
    }

    fn is_zero(&self) -> bool {
        self == &Self::ZERO
    }
}

impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};

        struct U64TokenVisitor;

        impl<'de> Visitor<'de> for U64TokenVisitor {
            type Value = U64;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("u64 or { e8s: u64 } struct")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U64(value))
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                use ic_ledger_core::tokens::Tokens;

                let tokens: Tokens =
                    Deserialize::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(U64(tokens.get_e8s()))
            }
        }

        deserializer.deserialize_any(U64TokenVisitor)
    }
}
