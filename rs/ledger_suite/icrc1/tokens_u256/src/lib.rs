use candid::Nat;
use ciborium::tag::Required;
use ethnum::u256;
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub, Zero};
use ic_stable_structures::storable::{Bound, Storable};
use num_traits::Bounded;
use serde::{
    de::{self, Deserializer},
    ser::Serializer,
    Deserialize, Serialize,
};
use std::borrow::Cow;
use std::fmt;

/// The tag number for big positive integers.
// See https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums
const BIGNUM_CBOR_TAG: u64 = 2;
const U64_MAX: u256 = u256::from_words(/* hi = */ 0, /* lo = */ u64::MAX as u128);

type TaggedRepr = Required<U256Repr, BIGNUM_CBOR_TAG>;

/// The representation of u256 used for serialization.
#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
#[serde(transparent)]
struct U256Repr(#[serde(with = "ethnum::serde::compressed_bytes::be")] u256);

/// 256-bit token amounts.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct U256(u256);

impl U256 {
    pub const ZERO: Self = Self(u256::ZERO);
    pub const ONE: Self = Self(u256::ONE);
    pub const MAX: Self = Self(u256::MAX);

    #[inline]
    pub const fn new(n: u256) -> Self {
        Self(n)
    }

    #[inline]
    pub const fn to_u256(self) -> u256 {
        self.0
    }

    #[inline]
    pub const fn from_words(hi: u128, lo: u128) -> Self {
        Self(u256::from_words(hi, lo))
    }

    #[inline]
    pub fn try_as_u64(&self) -> Option<u64> {
        if self.0 <= U64_MAX {
            Some(self.0.as_u64())
        } else {
            None
        }
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<u64> for U256 {
    fn from(n: u64) -> Self {
        Self(u256::from(n))
    }
}

impl From<u128> for U256 {
    fn from(n: u128) -> Self {
        Self(u256::from(n))
    }
}

impl From<U256> for Nat {
    fn from(n: U256) -> Self {
        use num_bigint::BigUint;
        candid::Nat(BigUint::from_bytes_le(&n.0.to_le_bytes()))
    }
}

impl TryFrom<Nat> for U256 {
    type Error = String;

    fn try_from(n: Nat) -> Result<Self, Self::Error> {
        let le_bytes = n.0.to_bytes_le();
        if le_bytes.len() > 32 {
            return Err(format!("amount {} does not fit into u256 token type", n));
        }
        let mut bytes = [0u8; 32];
        bytes[0..le_bytes.len()].copy_from_slice(&le_bytes[..]);
        Ok(Self::new(u256::from_le_bytes(bytes)))
    }
}

impl Storable for U256 {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.to_be_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        assert_eq!(bytes.len(), 32, "u256 representation is 32-bytes long");
        let mut be_bytes = [0u8; 32];
        be_bytes.copy_from_slice(bytes.as_ref());
        Self(u256::from_be_bytes(be_bytes))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 32,
        is_fixed_size: true,
    };
}

impl Bounded for U256 {
    fn min_value() -> Self {
        Self::ZERO
    }

    fn max_value() -> Self {
        Self::MAX
    }
}

impl CheckedAdd for U256 {
    fn checked_add(&self, other: &Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }
}

impl CheckedSub for U256 {
    fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

impl Zero for U256 {
    fn zero() -> Self {
        Self::ZERO
    }

    fn is_zero(&self) -> bool {
        self == &Self::ZERO
    }
}

impl From<TaggedRepr> for U256 {
    fn from(Required(U256Repr(n)): TaggedRepr) -> Self {
        Self(n)
    }
}

impl From<U256> for TaggedRepr {
    fn from(U256(n): U256) -> Self {
        Self(U256Repr(n))
    }
}

impl Serialize for U256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.try_as_u64() {
            Some(n) => serializer.serialize_u64(n),
            None => TaggedRepr::from(*self).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for U256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct U256Visitor;

        impl<'de> de::Visitor<'de> for U256Visitor {
            type Value = U256;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an integer between 0 and 2^256")
            }

            // NB. Ciborium tagged values are represented as enums internally.
            fn visit_enum<E>(self, e: E) -> Result<Self::Value, E::Error>
            where
                E: de::EnumAccess<'de>,
            {
                let repr: TaggedRepr =
                    Deserialize::deserialize(de::value::EnumAccessDeserializer::new(e))?;
                Ok(repr.into())
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U256::from(value))
            }

            fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U256::from(value))
            }
        }

        deserializer.deserialize_any(U256Visitor)
    }
}
