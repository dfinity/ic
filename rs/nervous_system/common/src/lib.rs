use candid::{CandidType, Deserialize};
use dfn_core::api::{call, time_nanos, CanisterId};
use rust_decimal::Decimal;
use serde::Serialize;

use core::ops::{Add, AddAssign, Div, Mul, Sub};
use std::convert::TryInto;
use std::fmt::{self, Display, Formatter};

use ic_base_types::PrincipalId;
use ic_canister_log::{export, GlobalBuffer};
use ic_canisters_http_types::{HttpResponse, HttpResponseBuilder};
use ic_ic00_types::{CanisterIdRecord, CanisterStatusResultV2, IC_00};
use ic_ledger_core::Tokens;

pub mod ledger;
pub mod stable_mem_utils;

// 10^8
pub const E8: u64 = 100_000_000;

pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

// Useful as a piece of realistic test data.
pub const START_OF_2022_TIMESTAMP_SECONDS: u64 = 1641016800;

// The size of a WASM page in bytes, as defined by the WASM specification
#[cfg(any(target_arch = "wasm32"))]
const WASM_PAGE_SIZE_BYTES: usize = 65536;

#[macro_export]
macro_rules! assert_is_ok {
    ($result: expr) => {
        let r = $result;
        assert!(
            r.is_ok(),
            "result ({}) = {:#?}, not Ok",
            stringify!($result),
            r
        );
    };
}

#[macro_export]
macro_rules! assert_is_err {
    ($result: expr) => {
        let r = $result;
        assert!(
            r.is_err(),
            "result ({}) = {:#?}, not Err",
            stringify!($result),
            r
        );
    };
}

pub fn i2d(i: u64) -> Decimal {
    // Convert to i64.
    let i = i
        .try_into()
        .unwrap_or_else(|err| panic!("{} does not fit into i64: {:#?}", i, err));

    Decimal::new(i, 0)
}

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

/// The operation to execute. Variable names in comments refer to the fields
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
pub async fn get_canister_status(
    canister_id: PrincipalId,
) -> Result<CanisterStatusResultV2, (Option<i32>, String)> {
    let canister_id_record: CanisterIdRecord = CanisterId::new(canister_id).unwrap().into();

    call(
        IC_00,
        "canister_status",
        dfn_candid::candid,
        (canister_id_record,),
    )
    .await
}

/// A more convenient (but explosive) way to do token math. Not suitable for
/// production use! Only for use in tests.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ExplosiveTokens(Tokens);

impl Display for ExplosiveTokens {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl From<Tokens> for ExplosiveTokens {
    fn from(src: Tokens) -> Self {
        Self(src)
    }
}

impl From<ExplosiveTokens> for Tokens {
    fn from(src: ExplosiveTokens) -> Self {
        src.0
    }
}

impl ExplosiveTokens {
    pub fn from_e8s(e8s: u64) -> Self {
        Self::from(Tokens::from_e8s(e8s))
    }

    // Same as get_e8s. This interface is more consistent with from_e8s.
    pub fn into_e8s(self) -> u64 {
        self.get_e8s()
    }

    // Like Tokens::get_e8s.
    pub fn get_e8s(self) -> u64 {
        self.0.get_e8s()
    }

    // {add,sub,mul,div)_or_die . Notice that unlike Tokens, these all return
    // Self, not Result.

    pub fn add_or_die(self, other: Self) -> Self {
        let result = Tokens::from(self) + Tokens::from(other);
        result.unwrap().into()
    }

    pub fn sub_or_die(self, other: Self) -> Self {
        let result = Tokens::from(self) - Tokens::from(other);
        result.unwrap().into()
    }

    pub fn mul_or_die(self, other: u64) -> Self {
        let result_e8s = self.into_e8s().checked_mul(other).unwrap();
        Self::from_e8s(result_e8s)
    }

    pub fn div_or_die(self, other: u64) -> Self {
        let result_e8s = self.into_e8s().checked_div(other).unwrap();
        Self::from_e8s(result_e8s)
    }

    // This is a bit special and is an interface optimization that serves a
    // common use case: proportional scaling. E.g. Suppose you have two
    // accounts, one with 100 ICP and aother with 200 ICP. From these two
    // sources, you want to raise 30 ICP. If you want the accounts to be used
    // "proportionally", then you'd source 10 ICP from the first account, and 20
    // ICP from the second. To calculate these, you would do
    //
    //   let total = all_accounts.iter().map(|a| a.balance).sum();
    //   fundraising_amount.mul_div_or_die(account.balance, total)
    //
    // In addition to being more convenient, this avoids the mistake of dividing
    // first, which results in more rounding errors.
    pub fn mul_div_or_die(self, mul: u64, div: u64) -> Self {
        let mul = mul as u128;
        let div = div as u128;

        let result_e8s = self.get_e8s() as u128 * mul / div;
        assert!(result_e8s <= u64::MAX as u128);
        Self::from_e8s(result_e8s as u64)
    }
}

// Operator Support

impl Add for ExplosiveTokens {
    type Output = Self;

    fn add(self, left: Self) -> Self {
        self.add_or_die(left)
    }
}

impl Sub for ExplosiveTokens {
    type Output = Self;

    fn sub(self, left: Self) -> Self {
        self.sub_or_die(left)
    }
}

impl Mul<u64> for ExplosiveTokens {
    type Output = Self;

    fn mul(self, left: u64) -> Self {
        self.mul_or_die(left)
    }
}

impl Div<u64> for ExplosiveTokens {
    type Output = Self;

    fn div(self, left: u64) -> Self {
        self.div_or_die(left)
    }
}

impl AddAssign for ExplosiveTokens {
    fn add_assign(&mut self, right: Self) {
        self.0 += right.0;
    }
}

// TODO: Implement other (Sub|Mul|Div)Assign traits. Also, std::iter::Sum.

// Return an HttpResponse that lists the given logs
pub fn serve_logs(logs: &'static GlobalBuffer) -> HttpResponse {
    use std::io::Write;
    let mut buf = vec![];
    for entry in export(logs) {
        writeln!(
            &mut buf,
            "{} {}:{} {}",
            entry.timestamp, entry.file, entry.line, entry.message
        )
        .unwrap();
    }

    HttpResponseBuilder::ok()
        .header("Content-Type", "text/plain; charset=utf-8")
        .with_body_and_content_length(buf)
        .build()
}

// Return an HttpResponse that lists this canister's metrics
pub fn serve_metrics(
    encode_metrics: impl FnOnce(&mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()>,
) -> HttpResponse {
    let mut writer =
        ic_metrics_encoder::MetricsEncoder::new(vec![], time_nanos() as i64 / 1_000_000);

    match encode_metrics(&mut writer) {
        Ok(()) => HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain; version=0.0.4")
            .with_body_and_content_length(writer.into_inner())
            .build(),
        Err(err) => {
            HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err)).build()
        }
    }
}

/// Verifies that the url is within the allowed length, and begins with
/// `http://` or `https://`. In addition, it will return an error in case of a
/// possibly "dangerous" condition, such as the url containing a username or
/// password, or having a port, or not having a domain name.
pub fn validate_proposal_url(
    url: &str,
    min_length: usize,
    max_length: usize,
    field_name: &str,
    allowed_domains: Option<Vec<&str>>,
) -> Result<(), String> {
    // // Check that the URL is a sensible length
    if url.len() > max_length {
        return Err(format!(
            "{field_name} must be less than {max_length} characters long, but it is {} characters long. (Field was set to `{url}`.)",
            url.len(),
        ));
    }
    if url.len() < min_length {
        return Err(format!(
            "{field_name} must be greater or equal to than {min_length} characters long, but it is {} characters long. (Field was set to `{url}`.)",
            url.len(),
        ));
    }

    //

    if !url.starts_with("https://") {
        return Err(format!(
            "{field_name} must begin with https://. (Field was set to `{url}`.)",
        ));
    }

    let parts_url: Vec<&str> = url.split("://").collect();
    if parts_url.len() > 2 {
        return Err(format!(
            "{field_name} contains an invalid sequence of characters"
        ));
    }

    if parts_url.len() < 2 {
        return Err(format!("{field_name} is missing content after protocol."));
    }

    if url.contains('@') {
        return Err(format!(
            "{field_name} cannot contain authentication information"
        ));
    }

    let parts_past_protocol = parts_url[1].split_once('/');

    let (domain, _path) = match parts_past_protocol {
        Some((domain, path)) => (domain, Some(path)),
        None => (parts_url[1], None),
    };

    match allowed_domains {
        Some(allowed) => match allowed.iter().any(|allowed| domain == *allowed) {
            true => Ok(()),
            false => Err(format!(
                "{field_name} was not in the list of allowed domains: {:?}",
                allowed
            )),
        },
        None => Ok(()),
    }
}

/// Returns the total amount of memory (heap, stable memory, etc) that the calling canister has allocated.
#[cfg(any(target_arch = "wasm32"))]
pub fn total_memory_size_bytes() -> usize {
    core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn total_memory_size_bytes() -> usize {
    0
}

/// Returns the amount of stable memory that the calling canister has allocated.
#[cfg(any(target_arch = "wasm32"))]
pub fn stable_memory_size_bytes() -> usize {
    dfn_core::api::stable_memory_size_in_pages() as usize * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn stable_memory_size_bytes() -> usize {
    0
}
