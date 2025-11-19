use candid::{CandidType, Nat};
use ic_stable_structures::{Storable, storable::Bound};
use minicbor::{Decode, Encode};
use num_traits::{Bounded, ToPrimitive};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::fmt;
use std::fmt::Debug;

#[cfg(test)]
mod tests;

/// Performs addition that returns `None` instead of wrapping around on
/// overflow.
///
/// The difference with `num_traits::CheckedAdd` is that this one dropped
/// the requirements that `Self` implements `Add`.
pub trait CheckedAdd: Sized {
    /// Adds two numbers, checking for overflow. If overflow happens, `None` is
    /// returned.
    fn checked_add(&self, v: &Self) -> Option<Self>;
}

impl<T> CheckedAdd for T
where
    T: num_traits::CheckedAdd,
{
    fn checked_add(&self, v: &Self) -> Option<Self> {
        self.checked_add(v)
    }
}

/// Performs subtraction that returns `None` instead of wrapping around on underflow.
///
/// The difference with `num_traits::CheckedSub` is that this one dropped
/// the requirements that `Self` implements `Sub`.
pub trait CheckedSub: Sized {
    /// Subtracts two numbers, checking for underflow. If underflow happens,
    /// `None` is returned.
    fn checked_sub(&self, v: &Self) -> Option<Self>;
}

impl<T> CheckedSub for T
where
    T: num_traits::CheckedSub,
{
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        self.checked_sub(v)
    }
}

/// Defines the identity of `Self` for [`CheckedAdd::checked_add()`].
pub trait Zero: Sized + CheckedAdd {
    /// The identity of `Self` for [`CheckedAdd::checked_add()`]
    fn zero() -> Self;

    /// Returns `true` if `self` is equal to [`Zero::zero()`].
    fn is_zero(&self) -> bool;
}

impl<T> Zero for T
where
    T: CheckedAdd + num_traits::Zero,
{
    fn zero() -> Self {
        num_traits::Zero::zero()
    }

    fn is_zero(&self) -> bool {
        <Self as num_traits::Zero>::is_zero(self)
    }
}

pub trait TokensType:
    Bounded
    + CheckedAdd
    + CheckedSub
    + Zero
    + Clone
    + Debug
    + Into<Nat>
    + TryFrom<Nat, Error = String>
    + PartialEq
    + Eq
    + PartialOrd
    + Ord
    + Serialize
    + DeserializeOwned
    + std::hash::Hash
{
}

impl<T> TokensType for T where
    T: Bounded
        + CheckedAdd
        + CheckedSub
        + Zero
        + Clone
        + Debug
        + Into<Nat>
        + TryFrom<Nat, Error = String>
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Serialize
        + DeserializeOwned
        + std::hash::Hash
{
}

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
    Decode,
    Encode,
)]
pub struct Tokens {
    /// Number of 10^-8 Tokens.
    /// Named because the equivalent part of a Bitcoin is called a Satoshi
    #[n(0)]
    e8s: u64,
}

pub const DECIMAL_PLACES: u32 = 8;
/// How many times can Tokens be divided
pub const TOKEN_SUBDIVIDABLE_BY: u64 = 100_000_000;

impl Tokens {
    /// The maximum value of this construct is 2^64-1 E8s or Roughly 184
    /// Billion Tokens
    pub const MAX: Self = Tokens { e8s: u64::MAX };

    /// Construct a new instance of Tokens.
    /// This function will not allow you use more than 1 Tokens worth of E8s.
    pub fn new(tokens: u64, e8s: u64) -> Result<Self, String> {
        static CONSTRUCTION_FAILED: &str =
            "Constructing Token failed because the underlying u64 overflowed";

        let token_part = tokens
            .checked_mul(TOKEN_SUBDIVIDABLE_BY)
            .ok_or_else(|| CONSTRUCTION_FAILED.to_string())?;
        if e8s >= TOKEN_SUBDIVIDABLE_BY {
            return Err(format!(
                "You've added too many E8s, make sure there are less than {TOKEN_SUBDIVIDABLE_BY}"
            ));
        }
        let e8s = token_part
            .checked_add(e8s)
            .ok_or_else(|| CONSTRUCTION_FAILED.to_string())?;
        Ok(Self { e8s })
    }

    pub const ZERO: Self = Tokens { e8s: 0 };

    /// ```
    /// # use ic_ledger_core::Tokens;
    /// let token = Tokens::from_tokens(12).unwrap();
    /// assert_eq!(token.unpack(), (12, 0))
    /// ```
    pub fn from_tokens(tokens: u64) -> Result<Self, String> {
        Self::new(tokens, 0)
    }

    /// Construct Tokens from E8s, 10E8 E8s == 1 Token
    /// ```
    /// # use ic_ledger_core::Tokens;
    /// let tokens = Tokens::from_e8s(1200000200);
    /// assert_eq!(tokens.unpack(), (12, 200))
    /// ```
    pub const fn from_e8s(e8s: u64) -> Self {
        Tokens { e8s }
    }

    /// Gets the total number of whole Tokens
    /// ```
    /// # use ic_ledger_core::Tokens;
    /// let tokens = Tokens::new(12, 200).unwrap();
    /// assert_eq!(tokens.get_tokens(), 12)
    /// ```
    pub fn get_tokens(self) -> u64 {
        self.e8s / TOKEN_SUBDIVIDABLE_BY
    }

    /// Gets the total number of E8s
    /// ```
    /// # use ic_ledger_core::Tokens;
    /// let tokens = Tokens::new(12, 200).unwrap();
    /// assert_eq!(tokens.get_e8s(), 1200000200)
    /// ```
    pub const fn get_e8s(self) -> u64 {
        self.e8s
    }

    /// Gets the total number of E8s not part of a whole Token
    /// The returned amount is always in the half-open interval [0, 1 Token).
    /// ```
    /// # use ic_ledger_core::Tokens;
    /// let token = Tokens::new(12, 200).unwrap();
    /// assert_eq!(token.get_remainder_e8s(), 200)
    /// ```
    pub fn get_remainder_e8s(self) -> u64 {
        self.e8s % TOKEN_SUBDIVIDABLE_BY
    }

    /// This returns the number of Tokens and E8s
    /// ```
    /// # use ic_ledger_core::Tokens;
    /// let token = Tokens::new(12, 200).unwrap();
    /// assert_eq!(token.unpack(), (12, 200))
    /// ```
    pub fn unpack(self) -> (u64, u64) {
        (self.get_tokens(), self.get_remainder_e8s())
    }

    pub fn saturating_add(self, other: Tokens) -> Tokens {
        Tokens::from_e8s(self.e8s.saturating_add(other.e8s))
    }

    pub fn saturating_sub(self, other: Tokens) -> Tokens {
        Tokens::from_e8s(self.e8s.saturating_sub(other.e8s))
    }

    pub fn checked_div(self, other: u64) -> Option<Tokens> {
        self.e8s.checked_div(other).map(Tokens::from_e8s)
    }
}

impl CheckedAdd for Tokens {
    fn checked_add(&self, other: &Self) -> Option<Self> {
        self.e8s.checked_add(other.e8s).map(|e8s| Self { e8s })
    }
}

impl CheckedSub for Tokens {
    fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.e8s.checked_sub(other.e8s).map(|e8s| Self { e8s })
    }
}

impl Bounded for Tokens {
    fn min_value() -> Self {
        Tokens::ZERO
    }

    fn max_value() -> Self {
        Tokens::MAX
    }
}

impl Zero for Tokens {
    fn zero() -> Self {
        Tokens::ZERO
    }

    fn is_zero(&self) -> bool {
        self == &Tokens::ZERO
    }
}

/// ```
/// # use ic_ledger_core::Tokens;
/// let token = Tokens::new(12, 200).unwrap();
/// let s = format!("{}", token);
/// assert_eq!(&s[..], "12.00000200 Token")
/// ```
impl fmt::Display for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{:08} Token",
            self.get_tokens(),
            self.get_remainder_e8s()
        )
    }
}

impl TryFrom<Nat> for Tokens {
    type Error = String;

    fn try_from(value: Nat) -> Result<Self, Self::Error> {
        match value.0.to_u64() {
            Some(e8s) => Ok(Self { e8s }),
            None => Err(format!("value {value} is bigger than Tokens::max_value()")),
        }
    }
}

impl From<u64> for Tokens {
    fn from(value: u64) -> Self {
        Tokens::from_e8s(value)
    }
}

impl From<Tokens> for Nat {
    fn from(value: Tokens) -> Self {
        Nat::from(value.e8s)
    }
}

impl Storable for Tokens {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.e8s.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self {
            e8s: u64::from_le_bytes(bytes.into_owned().as_slice().try_into().unwrap()),
        }
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 8,
        is_fixed_size: true,
    };
}
