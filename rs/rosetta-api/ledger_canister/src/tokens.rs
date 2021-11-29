use candid::CandidType;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(
    Serialize,
    Deserialize,
    CandidType,
    Clone,
    Copy,
    Hash,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
)]
pub struct Tokens {
    /// Number of 10^-8 Tokens.
    /// Named because the equivalent part of a Bitcoin is called a Satoshi
    e8s: u64,
}

pub const DECIMAL_PLACES: u32 = 8;
/// How many times can Tokens be divided
pub const TOKEN_SUBDIVIDABLE_BY: u64 = 100_000_000;

/// This is 1/10,000th of an Token, this is probably more than it costs us to
/// store a transaction so it will likely come down in the future
pub const TRANSACTION_FEE: Tokens = Tokens { e8s: 10_000 };
pub const MIN_BURN_AMOUNT: Tokens = TRANSACTION_FEE;

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
                "You've added too many E8s, make sure there are less than {}",
                TOKEN_SUBDIVIDABLE_BY
            ));
        }
        let e8s = token_part
            .checked_add(e8s)
            .ok_or_else(|| CONSTRUCTION_FAILED.to_string())?;
        Ok(Self { e8s })
    }

    pub const ZERO: Self = Tokens { e8s: 0 };

    /// ```
    /// # use ledger_canister::Tokens;
    /// let token = Tokens::from_tokens(12).unwrap();
    /// assert_eq!(token.unpack(), (12, 0))
    /// ```
    pub fn from_tokens(tokens: u64) -> Result<Self, String> {
        Self::new(tokens, 0)
    }

    /// Construct Tokens from E8s, 10E8 E8s == 1 Token
    /// ```
    /// # use ledger_canister::Tokens;
    /// let tokens = Tokens::from_e8s(1200000200);
    /// assert_eq!(tokens.unpack(), (12, 200))
    /// ```
    pub const fn from_e8s(e8s: u64) -> Self {
        Tokens { e8s }
    }

    /// Gets the total number of whole Tokens
    /// ```
    /// # use ledger_canister::Tokens;
    /// let tokens = Tokens::new(12, 200).unwrap();
    /// assert_eq!(tokens.get_tokens(), 12)
    /// ```
    pub fn get_tokens(self) -> u64 {
        self.e8s / TOKEN_SUBDIVIDABLE_BY
    }

    /// Gets the total number of E8s
    /// ```
    /// # use ledger_canister::Tokens;
    /// let tokens = Tokens::new(12, 200).unwrap();
    /// assert_eq!(tokens.get_e8s(), 1200000200)
    /// ```
    pub const fn get_e8s(self) -> u64 {
        self.e8s
    }

    /// Gets the total number of E8s not part of a whole Token
    /// The returned amount is always in the half-open interval [0, 1 Token).
    /// ```
    /// # use ledger_canister::Tokens;
    /// let token = Tokens::new(12, 200).unwrap();
    /// assert_eq!(token.get_remainder_e8s(), 200)
    /// ```
    pub fn get_remainder_e8s(self) -> u64 {
        self.e8s % TOKEN_SUBDIVIDABLE_BY
    }

    /// This returns the number of Tokens and E8s
    /// ```
    /// # use ledger_canister::Tokens;
    /// let token = Tokens::new(12, 200).unwrap();
    /// assert_eq!(token.unpack(), (12, 200))
    /// ```
    pub fn unpack(self) -> (u64, u64) {
        (self.get_tokens(), self.get_remainder_e8s())
    }
}

impl Add for Tokens {
    type Output = Result<Self, String>;

    /// This returns a result, in normal operation this should always return Ok
    /// because of the cap in the total number of Tokens, but when dealing with
    /// money it's better to be safe than sorry
    fn add(self, other: Self) -> Self::Output {
        let e8s = self.e8s.checked_add(other.e8s).ok_or_else(|| {
            format!(
                "Add Token {} + {} failed because the underlying u64 overflowed",
                self.e8s, other.e8s
            )
        })?;
        Ok(Self { e8s })
    }
}

impl AddAssign for Tokens {
    fn add_assign(&mut self, other: Self) {
        *self = (*self + other).expect("+= panicked");
    }
}

impl Sub for Tokens {
    type Output = Result<Self, String>;

    fn sub(self, other: Self) -> Self::Output {
        let e8s = self.e8s.checked_sub(other.e8s).ok_or_else(|| {
            format!(
                "Subtracting Token {} - {} failed because the underlying u64 underflowed",
                self.e8s, other.e8s
            )
        })?;
        Ok(Self { e8s })
    }
}

impl SubAssign for Tokens {
    fn sub_assign(&mut self, other: Self) {
        *self = (*self - other).expect("-= panicked");
    }
}

/// ```
/// # use ledger_canister::Tokens;
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
