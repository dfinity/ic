use by_address::ByAddress;
use core::{
    cmp::Reverse,
    fmt::Debug,
    ops::{Add, AddAssign, Div, Mul, Sub},
};
use dfn_core::api::time_nanos;
use ic_base_types::CanisterId;
use ic_canister_log::{export, GlobalBuffer, LogBuffer, LogEntry};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_ledger_core::tokens::{CheckedAdd, CheckedSub};
use ic_ledger_core::Tokens;
use lazy_static::lazy_static;
use maplit::hashmap;
use num_traits::ops::inv::Inv;
use priority_queue::priority_queue::PriorityQueue;
use rust_decimal::Decimal;
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::{self, Display, Formatter},
    mem::size_of,
    str::FromStr,
};

pub mod binary_search;
pub mod cmc;
pub mod dfn_core_stable_mem_utils;
pub mod ledger;
pub mod ledger_validation;
pub mod memory_manager_upgrade_storage;

pub mod tla_macros;

lazy_static! {
    // 10^-4. There is one ten-thousandth of a unit in one permyriad.
    pub static ref UNITS_PER_PERMYRIAD: Decimal = Decimal::from(10_000_u64).inv();

    // Includes 0, all powers of 2 (including 1), and u64::MAX, plus values around the
    // aforementioned numbers. This is useful for tests.
    pub static ref WIDE_RANGE_OF_U64_VALUES: Vec<u64> = (0..=64)
        .flat_map(|i| {
            let pow_of_two: i128 = 2_i128.pow(i);
            let perturbations = vec![-42, -7, -3, -2, -1, 0, 1, 2, 3, 7, 42];

            perturbations
                .into_iter()
                .map(|perturbation| {
                    pow_of_two
                        .saturating_add(perturbation)
                        .clamp(0, u64::MAX as i128) as u64
                })
                .collect::<Vec<u64>>()
        })
        .collect();

    pub static ref NNS_DAPP_BACKEND_CANISTER_ID: CanisterId =
        CanisterId::from_str("qoctq-giaaa-aaaaa-aaaea-cai").unwrap();
}

// 10^8
pub const E8: u64 = 100_000_000;

pub const DEFAULT_TRANSFER_FEE: Tokens = Tokens::from_e8s(10_000);

pub const ONE_DAY_SECONDS: u64 = 24 * 60 * 60;
pub const ONE_YEAR_SECONDS: u64 = (4 * 365 + 1) * ONE_DAY_SECONDS / 4;
pub const ONE_MONTH_SECONDS: u64 = ONE_YEAR_SECONDS / 12;

// Useful as a piece of realistic test data.
pub const START_OF_2022_TIMESTAMP_SECONDS: u64 = 1641016800;

pub const ONE_TRILLION: u64 = 1_000_000_000_000;

/// The number of cycles required to create an SNS, charged by the SNS-W canister.
pub const SNS_CREATION_FEE: u64 = 180 * ONE_TRILLION;

// The number of nanoseconds per second.
pub const NANO_SECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Maximum allowed number of SNS neurons for direct swap participants that an SNS may create.
/// This constant must not exceed `NervousSystemParameters::MAX_NUMBER_OF_NEURONS_CEILING`.
pub const MAX_NEURONS_FOR_DIRECT_PARTICIPANTS: u64 = 100_000;

// The size of a WASM page in bytes, as defined by the WASM specification
#[cfg(target_arch = "wasm32")]
const WASM_PAGE_SIZE_BYTES: usize = 65536;

// 1 Mi. Approximately 10^6, 1 million (slightly more).
const MAX_LOGS_RESPONSE_SIZE: usize = 1 << 20;

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

pub fn obsolete_string_field<T: AsRef<str>>(obselete_field: T, replacement: Option<T>) -> String {
    match replacement {
        Some(replacement) => format!(
            "The field `{}` is obsolete. Please use `{}` instead.",
            obselete_field.as_ref(),
            replacement.as_ref(),
        ),
        None => format!("The field `{}` is obsolete.", obselete_field.as_ref()),
    }
}

/// Besides dividing, this also converts to Decimal (from u64).
///
/// The only way this can fail is if denominations_per_token is 0. Therefore, if you pass a positive
/// constant (e.g. E8) for denominations_per_token, you do not have to implement clean up/recovery
/// in case of None. E.g. you can use unwrap_or_default.
pub fn denominations_to_tokens(
    denominations: u64,
    denominations_per_token: u64,
) -> Option<Decimal> {
    let denominations = Decimal::from(denominations);
    let denominations_per_token = Decimal::from(denominations_per_token);

    // denominations * tokens_per_denomination
    denominations.checked_div(denominations_per_token)
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

/// A more convenient (but explosive) way to do token math. Not suitable for
/// production use! Only for use in tests.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
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
        Tokens::from(self)
            .checked_add(&Tokens::from(other))
            .unwrap()
            .into()
    }

    pub fn sub_or_die(self, other: Self) -> Self {
        Tokens::from(self)
            .checked_sub(&Tokens::from(other))
            .unwrap()
            .into()
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
    // accounts, one with 100 ICP and another with 200 ICP. From these two
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
        self.0 = self.0.checked_add(&right.0).unwrap();
    }
}

// TODO: Implement other (Sub|Mul|Div)Assign traits. Also, std::iter::Sum.

// The "right" way to implement this is to use the url crate, but that causes
// our WASMs to be inordinately larger.
fn query_parameters_map(url: &str) -> HashMap<String, String> {
    const QUERY_SEPARATOR: &str = "?";
    let mut it = url.split(QUERY_SEPARATOR);
    let _skip = it.next();
    let query_string = it.next().unwrap_or_default();

    let mut result = HashMap::new();
    if query_string.is_empty() {
        return result;
    }

    const PARAMETER_SEPARATOR: &str = "&";
    for chunk in query_string.split(PARAMETER_SEPARATOR) {
        const KEY_VALUE_SEPARATOR: &str = "=";
        let mut split = chunk.splitn(2, KEY_VALUE_SEPARATOR);
        let name = split
            .next()
            .expect("Unable to get head of split (this should be impossible).");
        let value = split.next().unwrap_or_default();
        result.insert(name.to_string(), value.to_string());
    }

    result
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, serde::Serialize)]
enum LogSeverity {
    Info,
    Error,
}

impl FromStr for LogSeverity {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, /* description */ String> {
        let severity = match name {
            "Info" => Self::Info,
            "Error" => Self::Error,
            _ => return Err(format!("Unknown log severity name: {}", name)),
        };

        Ok(severity)
    }
}

impl Display for LogSeverity {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let s = match self {
            Self::Info => "Info",
            Self::Error => "Error",
        };

        write!(formatter, "{}", s)
    }
}

struct LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    severity: LogSeverity,
    head: Option<&'a LogEntry>,
    tail: I,
}

impl<'a, I> LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    fn new(severity: LogSeverity, mut tail: I) -> Self {
        let head = tail.next();
        Self {
            severity,
            head,
            tail,
        }
    }

    /// Based on the timestamp of the head log entry; earlier entries have
    /// higher priority.
    fn priority(&self) -> impl Ord + Debug {
        Reverse(
            self.head
                .map(|log_entry| log_entry.timestamp)
                .unwrap_or_default(),
        )
    }
}

impl<'a, I> Iterator for LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    type Item = &'a LogEntry;

    fn next(&mut self) -> Option<&'a LogEntry> {
        let result = self.head;
        self.head = self.tail.next();
        result
    }
}

impl<'a, I> Debug for LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("LogIter")
            .field("severity", &self.severity)
            .field("head", &self.head)
            .field("tail", &"...")
            .finish()
    }
}

/// Like LogEntry, but with severity.
#[derive(serde::Serialize)]
struct EnhancedLogEntry<'a> {
    severity: LogSeverity,
    timestamp: u64,
    file: &'static str,
    line: u32,
    message: &'a String,
}

impl<'a> EnhancedLogEntry<'a> {
    fn new(severity: LogSeverity, log_entry: &'a LogEntry) -> Self {
        // If the definition of LogEntry is ever changed, this will need to be
        // updated.
        let LogEntry {
            timestamp,
            file,
            line,
            message,
            ..
        } = log_entry;

        let timestamp = *timestamp;
        let line = *line;

        Self {
            severity,
            timestamp,
            file,
            line,
            message,
        }
    }

    fn approximate_size(&self) -> usize {
        let min = size_of::<LogSeverity>() // severity
            + size_of::<u64>() // timestamp
            + self.file.len()
            + size_of::<u32>() // line
            + self.message.len();

        // 1.33x factor of safety, because JSON serialization has some overhead
        // (because of quotes, spaces, colons, etc.).
        min * 4 / 3
    }
}

/// Fields are query parameters. See serve_logs_v2.
///
/// This does two main things:
///
///   1. Tries to convert from a generic HttpRequest (via impl From<HttpRequest>).
///
///   2. Renders JSON (via LogsRequest::render_json). Of course, this needs to
///      be fed logs.
struct LogsRequest {
    severity: LogSeverity,
    time: u64,
    // TODO: limit
}

impl LogsRequest {
    /// Returns JSON serialized response body, based on parameters in self.
    ///
    /// This is not entirely straightforward because this needs to do two
    /// things:
    ///
    ///     a. Merge INFO and ERROR logs (in the future, adding more severity levels
    ///        is would be pretty straightfroward).
    ///
    ///     b. Implement the filtering specified by the query parameters.
    pub fn render_json(&self, info_logs: &LogBuffer, error_logs: &LogBuffer) -> String {
        let mut info_logs = LogIter::new(LogSeverity::Info, self.skip_old_log_entries(info_logs));
        let mut error_logs =
            LogIter::new(LogSeverity::Error, self.skip_old_log_entries(error_logs));

        // Select sources. They will be merged later.
        // Prioritize them by the timestamp of their first element.
        let mut sources = PriorityQueue::new();
        {
            let info_priority = info_logs.priority();
            let error_priority = error_logs.priority();
            match self.severity {
                LogSeverity::Info => {
                    sources.push(ByAddress(&mut info_logs), info_priority);
                    sources.push(ByAddress(&mut error_logs), error_priority);
                }
                LogSeverity::Error => {
                    sources.push(ByAddress(&mut error_logs), error_priority);
                }
            }
        }

        // Merge sources by timestamp.
        let mut approximate_total_size = 0;
        let mut interleaved_logs = vec![];
        loop {
            // PriorityQueue::pop removes the element with the highest priority.
            // We prioritize by Reverse(first_log_entry.timestamp). See
            // LogIter::priority. Therefore, this should be an Iterator with the
            // earliest first LogEntry.
            let mut log_iter = match sources.pop() {
                None => break, // No more sources.
                Some((log_iter, _priority)) => log_iter,
            };

            let log_entry = match log_iter.next() {
                Some(log_entry) => log_entry,
                None => continue,
            };

            let enhanced_log_entry = EnhancedLogEntry::new(log_iter.severity, log_entry);
            approximate_total_size += enhanced_log_entry.approximate_size();
            if approximate_total_size > MAX_LOGS_RESPONSE_SIZE {
                break;
            }
            interleaved_logs.push(enhanced_log_entry);

            if log_iter.head.is_some() {
                // This guard is a minor optimization, because earlier in this
                // loop continue handles log_iter being empty.
                let priority = log_iter.priority();
                sources.push(log_iter, priority);
            }
        }

        serde_json::json!({
            "entries": interleaved_logs,
        })
        .to_string()
    }

    fn skip_old_log_entries<'a>(
        &self,
        log_buffer: &'a LogBuffer,
    ) -> impl Iterator<Item = &'a LogEntry> {
        let max_skip_timestamp = self.time;
        log_buffer
            .entries_partition_point(move |log_entry| log_entry.timestamp <= max_skip_timestamp)
    }
}

impl TryFrom<HttpRequest> for LogsRequest {
    // Describes what's wrong.
    type Error = String;

    fn try_from(http_request: HttpRequest) -> Result<Self, /* description */ String> {
        // Parse query parameters.
        let query = query_parameters_map(&http_request.url);

        let severity = query
            .get("severity")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "Info".to_string());
        let time = query
            .get("time")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string());

        let mut defects = vec![];

        let severity = match LogSeverity::from_str(&severity) {
            Ok(severity) => severity,
            Err(err) => {
                defects.push(format!(
                    "Invalid value for query parameter `severity` ({}): {}",
                    severity, err,
                ));
                // Dummy value; won't actually be used, because defects is now nonempty.
                LogSeverity::Info
            }
        };

        let time = match u64::from_str(&time) {
            Ok(time) => time,
            Err(err) => {
                defects.push(format!(
                    "Invalid value for query parameter `time` ({}): {}",
                    time, err,
                ));
                // Dummy value; won't actually be used, because defects is now nonempty.
                0
            }
        };

        let good = defects.is_empty();
        if !good {
            return Err(format!(
                "Invalid request for the following reason(s):\n  -{}",
                defects.join("\n  -"),
            ));
        }

        Ok(Self { severity, time })
    }
}

/// Supported query parameters (last occurrence wins):
///   severity:
///     possible values: Info (default), Error (More could be added later.)
///     meaning: Selects messages of the same or greater severity.
///   time:
///     value: integer nanoseconds since UNIX epoch. Default: 0.
///     meaning: Selects messages that are strictly more recent than this
///       (i.e. have timestamp greater than this).  Old messages may have been
///       dropped already.
///
/// The JSON response looks like this:
///   {
///     entries: [
///       {
///         timestamp: nanoseconds_since_unix_epoch,  // Chronological. > time query parameter.
///         severity: "Info" or "Error", // In the future we might add others. E.g. Warn, Debug, Fatal, etc...
///         file: path,
///         line: integer,
///         message: "Hello, world!",
///       },
///       // Etc.
///     ],
///   }
pub fn serve_logs_v2(
    request: HttpRequest,
    info_logs: &'static GlobalBuffer,
    error_logs: &'static GlobalBuffer,
) -> HttpResponse {
    // Convert from generic HTTP request to LogsRequest.
    let request = match LogsRequest::try_from(request) {
        Ok(request) => request,
        Err(message) => {
            let body = hashmap! {
                "error_description" => message,
            };
            return HttpResponseBuilder::bad_request()
                .header("Content-Type", "application/json")
                .with_body_and_content_length(json5::to_string(&body).unwrap_or_default())
                .build();
        }
    };

    let body = info_logs.with(|info_logs| {
        let info_logs = info_logs.borrow();
        error_logs.with(|error_logs| {
            let error_logs = error_logs.borrow();

            request.render_json(&info_logs, &error_logs)
        })
    });

    HttpResponseBuilder::ok()
        .header("Content-Type", "application/json")
        .with_body_and_content_length(body)
        .build()
}

/// Deprecated. Use serve_logs_v2 instead.
/// Returns an HttpResponse that lists the given logs.
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
#[cfg(target_arch = "wasm32")]
pub fn total_memory_size_bytes() -> usize {
    core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn total_memory_size_bytes() -> usize {
    0
}

/// Returns the number of stable memory pages that the calling canister has allocated.
#[cfg(target_arch = "wasm32")]
pub fn stable_memory_num_pages() -> u64 {
    dfn_core::stable::stable64_size()
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn stable_memory_num_pages() -> u64 {
    0
}

/// Returns the amount of stable memory that the calling canister has allocated.
#[cfg(target_arch = "wasm32")]
pub fn stable_memory_size_bytes() -> u64 {
    dfn_core::stable::stable64_size() * (WASM_PAGE_SIZE_BYTES as u64)
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn stable_memory_size_bytes() -> u64 {
    0
}

// Given 2 numbers `dividend`` and `divisor`, break the dividend to `divisor * quotient + remainder`
// where `remainder < divisor`, using safe arithmetic. Returns `(quotient, remainder)`.
fn checked_div_mod(dividend: usize, divisor: usize) -> Option<(usize, usize)> {
    let quotient = dividend.checked_div(divisor)?;
    let remainder = dividend.checked_rem(divisor)?;
    Some((quotient, remainder))
}

#[cfg(test)]
mod serve_logs_tests;

#[cfg(test)]
mod tests;
