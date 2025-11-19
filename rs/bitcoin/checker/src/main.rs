use bitcoin::{Address, Transaction, consensus::Decodable};
use candid::Nat;
use fetch::{FetchEnv, FetchResult, TryFetchResult, check_for_blocked_input_addresses};
use ic_btc_checker::{
    BtcNetwork, CHECK_TRANSACTION_CYCLES_REQUIRED, CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
    CheckAddressArgs, CheckAddressResponse, CheckArg, CheckMode, CheckTransactionArgs,
    CheckTransactionIrrecoverableError, CheckTransactionQueryArgs, CheckTransactionQueryResponse,
    CheckTransactionResponse, CheckTransactionRetriable, CheckTransactionStatus,
    CheckTransactionStrArgs, RETRY_MAX_RESPONSE_BYTES, blocklist::is_blocked,
};
use ic_btc_interface::Txid;
use ic_canister_log::{export as export_logs, log};
use ic_cdk::call::Error;
use ic_cdk::management_canister::TransformArgs;
use ic_http_types as http;
use ic_management_canister_types::HttpRequestResult;
use logs::{DEBUG, Log, LogEntry, Priority, WARN};
use state::{Config, FetchGuardError, FetchTxStatus, HttpGetTxError, get_config, set_config};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

mod dashboard;
mod fetch;
mod logs;
mod providers;
mod state;

#[derive(PartialOrd, Ord, PartialEq, Eq)]
pub enum IcError {
    CallRejected {
        raw_reject_code: u32,
        reject_message: String,
    },
    CallPerformFailed,
}

#[derive(PartialOrd, Ord, PartialEq, Eq)]
enum HttpsOutcallStatus {
    ResponseTooLarge,
    IcError(IcError),
    HttpStatusCode(Nat),
}

impl fmt::Display for HttpsOutcallStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ResponseTooLarge => write!(f, "ResponseTooLarge"),
            Self::IcError(ic_error) => match ic_error {
                IcError::CallRejected {
                    raw_reject_code, ..
                } => write!(f, "IcErrorCallRejected({raw_reject_code})"),
                IcError::CallPerformFailed => write!(f, "IcErrorCallPerformFailed"),
            },
            Self::HttpStatusCode(status_code) => write!(f, "HttpStatusCode({status_code})"),
        }
    }
}

#[derive(Default)]
struct Stats {
    https_outcall_status: BTreeMap<(String, HttpsOutcallStatus), u64>,
    http_response_size: BTreeMap<u32, u64>,
    check_transaction_count: u64,
}

thread_local! {
    static STATS : RefCell<Stats> = RefCell::default();
}

pub fn is_response_too_large(reject: &ic_cdk::call::CallRejected) -> bool {
    match reject.reject_code() {
        Ok(ic_cdk::call::RejectCode::SysFatal) => {
            let message = reject.reject_message();
            message.contains("size limit") || message.contains("length limit")
        }
        _ => false,
    }
}

/// Return `Passed` if the given bitcion address passed the check, or
/// `Failed` otherwise.
/// May throw error (trap) if the given address is malformed or not a mainnet address.
#[ic_cdk::query]
fn check_address(args: CheckAddressArgs) -> CheckAddressResponse {
    let config = get_config();
    let btc_network = config.btc_network();
    let address = Address::from_str(args.address.trim())
        .unwrap_or_else(|err| ic_cdk::trap(format!("Invalid Bitcoin address: {err}")))
        .require_network(btc_network.clone().into())
        .unwrap_or_else(|err| ic_cdk::trap(format!("Not a Bitcoin {btc_network} address: {err}")));

    match config.check_mode {
        CheckMode::AcceptAll => CheckAddressResponse::Passed,
        CheckMode::RejectAll => CheckAddressResponse::Failed,
        CheckMode::Normal => {
            if is_blocked(&address) {
                return CheckAddressResponse::Failed;
            }
            CheckAddressResponse::Passed
        }
    }
}

/// Return `Passed` if all input addresses of the transaction of the given
/// transaction id passed the check, or `Failed` if any of them did not.
///
/// Every call to check_transaction must attach at least `CHECK_TRANSACTION_CYCLES_REQUIRED`.
/// Return `NotEnoughCycles` if not enough cycles are attached.
///
/// The actual cycle cost may be well less than `CHECK_TRANSACTION_CYCLES_REQUIRED`, and
/// unspent cycles will be refunded back to the caller, minus a
/// `CHECK_TRANSACTION_CYCLES_SERVICE_FEE`, which is always deducted regardless.
///
/// In certain cases, it may also return `HighLoad` or `Pending` to indicate the
/// caller needs to call again (with at least `CHECK_TRANSACTION_CYCLES_REQUIRED` cycles)
/// in order to get the result.
///
/// If a permanent error occurred in the process, e.g, when a transaction data
/// fails to decode or its transaction id does not match, then `Error` is returned
/// together with a text description.
#[ic_cdk::update]
async fn check_transaction(args: CheckTransactionArgs) -> CheckTransactionResponse {
    check_transaction_with(|| Txid::try_from(args)).await
}

#[ic_cdk::update]
async fn check_transaction_str(args: CheckTransactionStrArgs) -> CheckTransactionResponse {
    check_transaction_with(|| Txid::try_from(args)).await
}

/// Performs the same logic as `check_transaction`, but only returns `Pass` or `Failed` if the
/// TXID and all of its inputs are available in the heap memory cache, meaning no HTTP outcalls are
/// performed. Returns `Unknown` if the transaction cannot be checked with only cached information.
#[ic_cdk::query]
async fn check_transaction_query(args: CheckTransactionQueryArgs) -> CheckTransactionQueryResponse {
    match Txid::try_from(args) {
        Ok(txid) => check_fetched_transaction_inputs(txid).await,
        Err(err) => panic!("Invalid transaction ID: {err}"),
    }
}

async fn check_transaction_with<F: FnOnce() -> Result<Txid, String>>(
    get_txid: F,
) -> CheckTransactionResponse {
    if ic_cdk::api::msg_cycles_accept(CHECK_TRANSACTION_CYCLES_SERVICE_FEE)
        < CHECK_TRANSACTION_CYCLES_SERVICE_FEE
    {
        return CheckTransactionStatus::NotEnoughCycles.into();
    }

    match get_txid() {
        Ok(txid) => {
            STATS.with(|s| s.borrow_mut().check_transaction_count += 1);
            if ic_cdk::api::msg_cycles_available()
                .checked_add(CHECK_TRANSACTION_CYCLES_SERVICE_FEE)
                .unwrap()
                < CHECK_TRANSACTION_CYCLES_REQUIRED
            {
                CheckTransactionStatus::NotEnoughCycles.into()
            } else {
                check_transaction_inputs(txid).await
            }
        }
        Err(err) => CheckTransactionIrrecoverableError::InvalidTransactionId(err).into(),
    }
}

#[ic_cdk::query(hidden = true)]
fn transform(raw: TransformArgs) -> HttpRequestResult {
    HttpRequestResult {
        status: raw.response.status.clone(),
        body: raw.response.body.clone(),
        headers: vec![],
    }
}

#[ic_cdk::init]
fn init(arg: Option<CheckArg>) {
    match arg {
        Some(CheckArg::InitArg(init_arg)) => set_config(
            Config::new_and_validate(
                init_arg.btc_network,
                init_arg.check_mode,
                init_arg.num_subnet_nodes,
            )
            .unwrap_or_else(|err| ic_cdk::trap(format!("error creating config: {err}"))),
        ),
        _ => {
            ic_cdk::trap("cannot init canister state without init args");
        }
    }
}

#[ic_cdk::post_upgrade]
fn post_upgrade(arg: Option<CheckArg>) {
    match arg {
        Some(CheckArg::UpgradeArg(arg)) => {
            let old_config = get_config();
            let num_subnet_nodes = arg
                .as_ref()
                .and_then(|arg| arg.num_subnet_nodes)
                .unwrap_or(old_config.num_subnet_nodes);
            let check_mode = arg
                .as_ref()
                .and_then(|arg| arg.check_mode)
                .unwrap_or(old_config.check_mode);
            let config =
                Config::new_and_validate(old_config.btc_network(), check_mode, num_subnet_nodes)
                    .unwrap_or_else(|err| ic_cdk::trap(format!("error creating config: {err}")));
            set_config(config);
        }
        Some(CheckArg::InitArg(_)) => {
            ic_cdk::trap("cannot upgrade canister state without upgrade args")
        }
        _ => (), // config remains unchanged if no upgrade argument is specified
    }
}

#[ic_cdk::query(hidden = true)]
fn http_request(req: http::HttpRequest) -> http::HttpResponse {
    if ic_cdk::api::in_replicated_execution() {
        ic_cdk::trap("update call rejected");
    }

    #[cfg(target_arch = "wasm32")]
    fn heap_memory_size_bytes() -> usize {
        const WASM_PAGE_SIZE_BYTES: usize = 65536;
        core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
    }

    #[cfg(not(any(target_arch = "wasm32")))]
    fn heap_memory_size_bytes() -> usize {
        0
    }

    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        let cycle_balance = ic_cdk::api::canister_cycle_balance() as f64;

        writer
            .gauge_vec("cycle_balance", "The canister cycle balance.")
            .unwrap()
            .value(&[("canister", "btc-checker")], cycle_balance)
            .unwrap();

        writer
            .encode_gauge(
                "heap_memory_bytes",
                heap_memory_size_bytes() as f64,
                "Size of the heap memory allocated by this canister.",
            )
            .unwrap();

        writer
            .encode_gauge(
                "stable_memory_bytes",
                ic_cdk::stable::stable_size() as f64 * 65536.0,
                "Size of the stable memory allocated by this canister.",
            )
            .unwrap();

        STATS.with(|s| {
            let stats = s.borrow();
            let mut counter = writer
                .counter_vec(
                    "btc_checker_http_calls_total",
                    "The number of http outcalls made since the last canister upgrade.",
                )
                .unwrap();
            for ((provider, status), count) in stats.https_outcall_status.iter() {
                counter = counter
                    .value(
                        &[
                            ("provider", provider.as_str()),
                            ("status", status.to_string().as_ref()),
                        ],
                        *count as f64,
                    )
                    .unwrap();
            }
            let mut counter = writer
                .counter_vec(
                    "btc_checker_http_response_size",
                    "The byte sizes of http outcall responses.",
                )
                .unwrap();
            for (size, count) in stats.http_response_size.iter() {
                counter = counter
                    .value(&[("size", size.to_string().as_str())], *count as f64)
                    .unwrap();
            }
            writer
                .counter_vec(
                    "btc_check_requests_total",
                    "The number of check requests received since the last canister upgrade.",
                )
                .unwrap()
                .value(
                    &[("type", "check_transaction")],
                    stats.check_transaction_count as f64,
                )
                .unwrap();
        });

        http::HttpResponseBuilder::ok()
            .header("Content-Type", "text/plain; version=0.0.4")
            .header("Cache-Control", "no-store")
            .with_body_and_content_length(writer.into_inner())
            .build()
    } else if req.path() == "/logs" {
        use serde_json;

        let max_skip_timestamp = match req.raw_query_param("time") {
            Some(arg) => match u64::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return http::HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'time' parameter")
                        .build();
                }
            },
            None => 0,
        };

        let mut entries: Log = Default::default();
        for entry in export_logs(&WARN) {
            if entry.timestamp >= max_skip_timestamp {
                entries.entries.push(LogEntry {
                    timestamp: entry.timestamp,
                    counter: entry.counter,
                    priority: Priority::Warn,
                    file: entry.file.to_string(),
                    line: entry.line,
                    message: entry.message,
                });
            }
        }
        for entry in export_logs(&DEBUG) {
            if entry.timestamp >= max_skip_timestamp {
                entries.entries.push(LogEntry {
                    timestamp: entry.timestamp,
                    counter: entry.counter,
                    priority: Priority::Debug,
                    file: entry.file.to_string(),
                    line: entry.line,
                    message: entry.message,
                });
            }
        }
        http::HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
            .build()
    } else if req.path() == "/dashboard" {
        use askama::Template;
        let page_index = match req.raw_query_param("page") {
            Some(arg) => match usize::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return http::HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'page' parameter")
                        .build();
                }
            },
            None => 0,
        };
        let dashboard = dashboard::dashboard(page_index).render().unwrap();
        http::HttpResponseBuilder::ok()
            .header("Content-Type", "text/html; charset=utf-8")
            .with_body_and_content_length(dashboard)
            .build()
    } else {
        http::HttpResponseBuilder::not_found().build()
    }
}

struct BtcCheckerCanisterEnv;

impl FetchEnv for BtcCheckerCanisterEnv {
    type FetchGuard = state::FetchGuard;

    fn new_fetch_guard(&self, txid: Txid) -> Result<Self::FetchGuard, FetchGuardError> {
        state::FetchGuard::new(txid)
    }

    fn config(&self) -> Config {
        get_config()
    }

    async fn http_get_tx(
        &self,
        provider: &providers::Provider,
        txid: Txid,
        max_response_bytes: u32,
    ) -> Result<Transaction, HttpGetTxError> {
        use ic_cdk::management_canister::http_request;
        let request = provider
            .create_request(txid, max_response_bytes)
            .map_err(|err| HttpGetTxError::Rejected {
                code: 1, //SYS_FATAL
                message: err,
            })?;
        let url = request.url.clone();
        match http_request(&request).await {
            Ok(response) => {
                STATS.with(|s| {
                    let mut stat = s.borrow_mut();
                    *stat
                        .https_outcall_status
                        .entry((
                            provider.name(),
                            HttpsOutcallStatus::HttpStatusCode(response.status.clone()),
                        ))
                        .or_default() += 1;
                    // Calculate size bucket as a series of power of 2s.
                    // Note that the max is bounded by `max_response_bytes`, which fits `u32`.
                    let size = 2u32.pow((response.body.len() as f64).log2().floor() as u32);
                    *stat.http_response_size.entry(size).or_default() += 1;
                });

                // Ensure response is 200 before decoding
                if response.status != 200u32 {
                    // All non-200 status are treated as transient errors
                    return Err(HttpGetTxError::Rejected {
                        code: 2, //SYS_TRANSIENT
                        message: format!("HTTP call {} received code {}", url, response.status),
                    });
                }
                let tx = match provider.btc_network() {
                    BtcNetwork::Regtest { .. } => {
                        use serde_json::{Value, from_slice, from_value};
                        let json: Value = from_slice(response.body.as_slice()).map_err(|err| {
                            HttpGetTxError::TxEncoding(format!("JSON parsing error {err}"))
                        })?;
                        let hex: String =
                            from_value(json["result"]["hex"].clone()).map_err(|_| {
                                HttpGetTxError::TxEncoding(
                                    "Missing result.hex field in JSON response".to_string(),
                                )
                            })?;
                        let raw = hex::decode(&hex).map_err(|err| {
                            HttpGetTxError::TxEncoding(format!("decode hex error: {err}"))
                        })?;
                        Transaction::consensus_decode(&mut raw.as_slice()).map_err(|err| {
                            HttpGetTxError::TxEncoding(format!("decode tx error: {err}"))
                        })?
                    }
                    _ => Transaction::consensus_decode(&mut response.body.as_slice())
                        .map_err(|err| HttpGetTxError::TxEncoding(err.to_string()))?,
                };
                // Verify the correctness of the transaction by recomputing the transaction ID.
                let decoded_txid = tx.compute_txid();
                if decoded_txid.as_ref() as &[u8; 32] != txid.as_ref() {
                    return Err(HttpGetTxError::TxidMismatch {
                        expected: txid,
                        decoded: Txid::from(*(decoded_txid.as_ref() as &[u8; 32])),
                    });
                }
                Ok(tx)
            }
            Err(ic_cdk::call::Error::CallRejected(reject)) if is_response_too_large(&reject) => {
                if max_response_bytes >= RETRY_MAX_RESPONSE_BYTES {
                    STATS.with(|s| {
                        let mut stat = s.borrow_mut();
                        *stat
                            .https_outcall_status
                            .entry((provider.name(), HttpsOutcallStatus::ResponseTooLarge))
                            .or_default() += 1;
                    });
                }
                Err(HttpGetTxError::ResponseTooLarge)
            }
            Err(error) => {
                let (status, http_error) = match error {
                    Error::InsufficientLiquidCycleBalance(e) => {
                        panic!("BUG: Insufficient liquidity balance: {}", e)
                    }
                    Error::CandidDecodeFailed(e) => {
                        panic!("BUG: Candid decoding http_request failed: {}", e)
                    }
                    Error::CallPerformFailed(_e) => (
                        HttpsOutcallStatus::IcError(IcError::CallPerformFailed),
                        HttpGetTxError::CallPerformFailed,
                    ),
                    Error::CallRejected(e) => (
                        HttpsOutcallStatus::IcError(IcError::CallRejected {
                            raw_reject_code: e.raw_reject_code(),
                            reject_message: e.reject_message().to_string(),
                        }),
                        HttpGetTxError::Rejected {
                            code: e.raw_reject_code(),
                            message: e.reject_message().to_string(),
                        },
                    ),
                };
                STATS.with(|s| {
                    let mut stat = s.borrow_mut();
                    *stat
                        .https_outcall_status
                        .entry((provider.name(), status))
                        .or_default() += 1;
                });
                log!(
                    DEBUG,
                    "The http_request resulted into error. Error: {http_error}, Request: {request:?}"
                );
                Err(http_error)
            }
        }
    }

    fn cycles_accept(&self, cycles: u128) -> u128 {
        ic_cdk::api::msg_cycles_accept(cycles)
    }
}

/// Check the input addresses of a transaction given its txid.
/// It consists of the following steps:
///
/// 1. Call `try_fetch_tx` to find if the transaction has already
///    been fetched, or if another fetch is already pending, or
///    if we are experiencing high load, or we need to retry the
///    fetch (when the previous max_response_bytes setting wasn't
///    enough).
///
/// 2. If we need to fetch this tranction, call the function `do_fetch`.
///
/// 3. For fetched transaction, call `check_fetched`, which further
///    checks if the input addresses of this transaction are available.
///    If not, we need to additionally fetch those input transactions
///    in order to compute their corresponding addresses.
pub async fn check_transaction_inputs(txid: Txid) -> CheckTransactionResponse {
    let env = &BtcCheckerCanisterEnv;
    match env.config().check_mode {
        CheckMode::AcceptAll => CheckTransactionResponse::Passed,
        CheckMode::RejectAll => CheckTransactionResponse::Failed(Vec::new()),
        CheckMode::Normal => {
            match env.try_fetch_tx(txid) {
                TryFetchResult::Pending => CheckTransactionRetriable::Pending.into(),
                TryFetchResult::HighLoad => CheckTransactionRetriable::HighLoad.into(),
                TryFetchResult::NotEnoughCycles => CheckTransactionStatus::NotEnoughCycles.into(),
                TryFetchResult::Fetched(fetched) => env.check_fetched(txid, &fetched).await,
                TryFetchResult::ToFetch(do_fetch) => {
                    match do_fetch.await {
                        Ok(FetchResult::Fetched(fetched)) => {
                            env.check_fetched(txid, &fetched).await
                        }
                        Ok(FetchResult::Error(err)) => err.into_response(txid),
                        Ok(FetchResult::RetryWithBiggerBuffer) => {
                            CheckTransactionRetriable::Pending.into()
                        }
                        Err(_) => unreachable!(), // should never happen
                    }
                }
            }
        }
    }
}

/// Check the input addresses of a transaction given its txid without performing any HTTP outcalls.
/// A `Pass` or `Fail` status will only be returned if the txid and all of its inputs were already
/// fetched and available in heap memory. Otherwise, `Unknown` is returned.
pub async fn check_fetched_transaction_inputs(txid: Txid) -> CheckTransactionQueryResponse {
    match BtcCheckerCanisterEnv.config().check_mode {
        CheckMode::AcceptAll => CheckTransactionQueryResponse::Passed,
        CheckMode::RejectAll => CheckTransactionQueryResponse::Failed(Vec::new()),
        CheckMode::Normal => match state::get_fetch_status(txid) {
            Some(FetchTxStatus::Fetched(fetched)) => {
                check_for_blocked_input_addresses(&fetched).into()
            }
            Some(
                FetchTxStatus::PendingOutcall
                | FetchTxStatus::PendingRetry { .. }
                | FetchTxStatus::Error(_),
            )
            | None => CheckTransactionQueryResponse::Unknown,
        },
    }
}

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{CandidSource, service_equal};

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("btc_checker_canister.did");

    service_equal(
        CandidSource::Text(dbg!(&new_interface)),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
