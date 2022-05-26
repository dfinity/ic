use candid::{CandidType, Deserialize};
use dfn_core::api::{call, CanisterId};
use num::{rational::Ratio, BigInt};
use serde::Serialize;

use std::fmt;
use std::fmt::Formatter;

use ic_base_types::PrincipalId;
use ic_ic00_types::{CanisterIdRecord, CanisterStatusResultV2, IC_00};

pub mod ledger;
pub mod stable_mem_utils;

/// A general purpose error indicating something went wrong.
#[derive(Default)]
pub struct NervousSystemError {
    pub error_message: String,
}

impl NervousSystemError {
    pub fn new() -> Self {
        NervousSystemError {
            ..Default::default()
        }
    }

    pub fn new_with_message(message: impl ToString) -> Self {
        NervousSystemError {
            error_message: message.to_string(),
        }
    }
}

impl fmt::Display for NervousSystemError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

impl fmt::Debug for NervousSystemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error_message)
    }
}

/// Description of a change to the authz of a specific method on a specific
/// canister that must happen for a given canister change/add/remove
/// to be viable
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct MethodAuthzChange {
    pub canister: CanisterId,
    pub method_name: String,
    pub principal: Option<PrincipalId>,
    pub operation: AuthzChangeOp,
}

/// The operation to execute. Varible names in comments refer to the fields
/// of AuthzChange.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum AuthzChangeOp {
    /// 'canister' must add a principal to the authorized list of 'method_name'.
    /// If 'add_self' is true, the canister_id to be authorized is the canister
    /// being added/changed, if it's false, 'principal' is used instead, which
    /// must be Some in that case..
    Authorize { add_self: bool },
    /// 'canister' must remove 'principal' from the authorized list of
    /// 'method_name'. 'principal' must always be Some.
    Deauthorize,
}

/// Return the status of the given canister. The caller must control the given canister.
pub async fn get_canister_status(canister_id: PrincipalId) -> CanisterStatusResultV2 {
    let canister_id_record: CanisterIdRecord = CanisterId::new(canister_id).unwrap().into();

    call(
        IC_00,
        "canister_status",
        dfn_candid::candid,
        (canister_id_record,),
    )
    .await
    .unwrap()
}

/// (Concisely) converts an integer to a rational.
///
/// You might be thinking, "wait, shouldn't the num library supply a conversion
/// function?". Well, it does, but it converts from I to Ratio<I> where I is
/// some primitive integer type, but we want to convert from I to Ratio<BigInt>
/// to avoid (or at least minimize) loss of precision. Eliminating (or at least
/// minimizing) loss of precision might be a little more expensive, but it is
/// gentler on the feeble human brain. Maybe, we could get away with using
/// Ratio<u64>, but why optimize prematurely, when it is a Well-Known Fact that
/// "premature optimization is the root of all evil"?
pub fn i2r(i: impl Into<BigInt>) -> Ratio<BigInt> {
    Ratio::from(i.into())
}

pub fn percent(i: impl Into<BigInt>) -> Ratio<BigInt> {
    i2r(i) / i2r(100)
}

/// Convert a rational number into a u64.
///
/// To successfully convert, the argument must
///
///   1. not have a fractional part (i.e. must be an actual integer), and
///   2. it must not overflow u64 (i.e. be <= max and >= min)
pub fn try_r2u64(r: &Ratio<BigInt>) -> anyhow::Result<u64> {
    let fract = r.fract();
    if fract != i2r(0) {
        anyhow::bail!(
            "Could not convert rational to u64, because a fractional part remains: {}",
            r
        );
    }

    if r < &i2r(0) {
        anyhow::bail!(
            "Could not convert rational to u64, because the argument is negative (underflow?): {}",
            r
        );
    }

    let (n, d) = r.clone().into();
    debug_assert_eq!(d, BigInt::from(1), "{:#?}", r);

    let mut chunks = n.iter_u64_digits();
    let first_chunk = chunks.next().unwrap_or(0);

    // Assert that there are no more chunks.
    let big_chunks = chunks.collect::<Vec<u64>>();
    if big_chunks != Vec::<u64>::new() {
        anyhow::bail!(
            "Could not convert rational to u64, because of overflow: {}",
            r
        );
    }

    Ok(first_chunk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_r2u64_ok() {
        for i in [0, 1, 2, 3, 42, u64::MAX - 1, u64::MAX] {
            assert!(try_r2u64(&i2r(i)).is_ok());
        }
    }

    #[test]
    fn try_r2u64_fract() {
        #![allow(clippy::approx_constant)]

        let five_fourths = i2r(5) / i2r(4);
        assert!(try_r2u64(&five_fourths).is_err());

        assert!(try_r2u64(&Ratio::from_float(3.14).unwrap()).is_err());
    }

    #[test]
    fn try_r2u64_negative() {
        assert!(try_r2u64(&i2r(-1)).is_err());
    }

    #[test]
    fn try_r2u64_too_big() {
        let slightly_too_large = i2r(u64::MAX) + i2r(1);
        assert!(try_r2u64(&slightly_too_large).is_err());
    }
}
