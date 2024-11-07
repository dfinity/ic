use bitcoin::{
    consensus::Decodable,
    Address,
    Transaction,
};
use ic_btc_interface::Txid;
use ic_btc_kyt::{
    blocklist_contains,
    get_tx_cycle_cost,
    BtcNetwork,
    CheckAddressArgs,
    CheckAddressResponse,
    CheckTransactionArgs,
    CheckTransactionIrrecoverableError,
    CheckTransactionResponse,
    CheckTransactionRetriable,
    CheckTransactionStatus,
    KytArg,
    KytMode,
    CHECK_TRANSACTION_CYCLES_REQUIRED,
    CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
};
use ic_canisters_http_types as http;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::http_request::{
    HttpResponse,
    TransformArgs,
};
use std::str::FromStr;

mod dashboard;
mod fetch;
mod providers;
mod state;

use fetch::{
    FetchEnv,
    FetchResult,
    TryFetchResult,
};
use state::{
    get_config,
    set_config,
    Config,
    FetchGuardError,
    HttpGetTxError,
};

pub fn is_response_too_large(code: &RejectionCode, message: &str) -> bool {
    code == &RejectionCode::SysFatal
        && (message.contains("size limit") || message.contains("length limit"))
}

#[ic_cdk::query]
/// Return `Passed` if the given bitcion address passed the KYT check, or
/// `Failed` otherwise.
/// May throw error (trap) if the given address is malformed or not a mainnet address.
fn check_address(args: CheckAddressArgs) -> CheckAddressResponse {
    let config = get_config();
    let btc_network = config.btc_network();
    let address = Address::from_str(args.address.trim())
        .unwrap_or_else(|err| ic_cdk::trap(&format!("Invalid bitcoin address: {}", err)))
        .require_network(btc_network.clone().into())
        .unwrap_or_else(|err| {
            ic_cdk::trap(&format!("Not a bitcoin {} address: {}", btc_network, err))
        });

    match config.kyt_mode() {
        KytMode::AcceptAll => CheckAddressResponse::Passed,
        KytMode::RejectAll => CheckAddressResponse::Failed,
        KytMode::Normal => {
            if blocklist_contains(&address) {
                return CheckAddressResponse::Failed;
            }
            CheckAddressResponse::Passed
        }
    }
}

#[ic_cdk::update]
/// Return `Passed` if all input addresses of the transaction of the given
/// transaction id passed the KYT check, or `Failed` if any of them did not.
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
async fn check_transaction(args: CheckTransactionArgs) -> CheckTransactionResponse {
    ic_cdk::api::call::msg_cycles_accept128(CHECK_TRANSACTION_CYCLES_SERVICE_FEE);
    match Txid::try_from(args.txid.as_ref()) {
        Ok(txid) => {
            if ic_cdk::api::call::msg_cycles_available128()
                .checked_add(CHECK_TRANSACTION_CYCLES_SERVICE_FEE)
                .unwrap()
                < CHECK_TRANSACTION_CYCLES_REQUIRED
            {
                CheckTransactionStatus::NotEnoughCycles.into()
            } else {
                check_transaction_inputs(txid).await
            }
        }
        Err(err) => {
            CheckTransactionIrrecoverableError::InvalidTransactionId(err.to_string()).into()
        }
    }
}

#[ic_cdk::query(hidden = true)]
fn transform(raw: TransformArgs) -> HttpResponse {
    HttpResponse {
        status: raw.response.status.clone(),
        body: raw.response.body.clone(),
        headers: vec![],
    }
}

#[ic_cdk::init]
fn init(arg: KytArg) {
    match arg {
        KytArg::InitArg(init_arg) => set_config(
            Config::new_and_validate(init_arg.btc_network, init_arg.kyt_mode)
                .unwrap_or_else(|err| ic_cdk::trap(&format!("error creating config: {}", err))),
        ),
        KytArg::UpgradeArg(_) => {
            ic_cdk::trap("cannot init canister state without init args");
        }
    }
}

#[ic_cdk::post_upgrade]
fn post_upgrade(arg: KytArg) {
    match arg {
        KytArg::UpgradeArg(arg) => {
            if let Some(kyt_mode) = arg.and_then(|arg| arg.kyt_mode) {
                let config = Config::new_and_validate(get_config().btc_network(), kyt_mode)
                    .unwrap_or_else(|err| ic_cdk::trap(&format!("error creating config: {}", err)));
                set_config(config);
            }
        }
        KytArg::InitArg(_) => ic_cdk::trap("cannot upgrade canister state without upgrade args"),
    }
}

#[ic_cdk::query(hidden = true)]
fn http_request(req: http::HttpRequest) -> http::HttpResponse {
    if req.path() == "/metrics" {
        // TODO(XC-205): Add metrics
        unimplemented!()
    } else if req.path() == "/dashboard" {
        use askama::Template;
        let page_index = match req.raw_query_param("page") {
            Some(arg) => match usize::from_str(arg) {
                Ok(value) => value,
                Err(_) => {
                    return http::HttpResponseBuilder::bad_request()
                        .with_body_and_content_length("failed to parse the 'page' parameter")
                        .build()
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

struct KytCanisterEnv;

impl FetchEnv for KytCanisterEnv {
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
        use ic_cdk::api::management_canister::http_request::http_request;
        let request = provider
            .create_request(txid, max_response_bytes)
            .map_err(|err| HttpGetTxError::Rejected {
                code: RejectionCode::SysFatal,
                message: err,
            })?;
        let url = request.url.clone();
        let cycles = get_tx_cycle_cost(max_response_bytes);
        match http_request(request.clone(), cycles).await {
            Ok((response,)) => {
                // Ensure response is 200 before decoding
                if response.status != 200u32 {
                    // All non-200 status are treated as transient errors
                    return Err(HttpGetTxError::Rejected {
                        code: RejectionCode::SysTransient,
                        message: format!("HTTP call {} received code {}", url, response.status),
                    });
                }
                let tx = match provider.btc_network() {
                    BtcNetwork::Regtest { .. } => {
                        use serde_json::{
                            from_slice,
                            from_value,
                            Value,
                        };
                        let json: Value = from_slice(response.body.as_slice()).map_err(|err| {
                            HttpGetTxError::TxEncoding(format!("JSON parsing error {}", err))
                        })?;
                        let hex: String =
                            from_value(json["result"]["hex"].clone()).map_err(|_| {
                                HttpGetTxError::TxEncoding(
                                    "Missing result.hex field in JSON response".to_string(),
                                )
                            })?;
                        let raw = hex::decode(&hex).map_err(|err| {
                            HttpGetTxError::TxEncoding(format!("decode hex error: {}", err))
                        })?;
                        Transaction::consensus_decode(&mut raw.as_slice()).map_err(|err| {
                            HttpGetTxError::TxEncoding(format!("decode tx error: {}", err))
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
            Err((r, m)) if is_response_too_large(&r, &m) => Err(HttpGetTxError::ResponseTooLarge),
            Err((r, m)) => {
                // TODO(XC-158): maybe try other providers and also log the error.
                println!("The http_request resulted into error. RejectionCode: {r:?}, Error: {m}");
                Err(HttpGetTxError::Rejected {
                    code: r,
                    message: m,
                })
            }
        }
    }

    fn cycles_accept(&self, cycles: u128) -> u128 {
        ic_cdk::api::call::msg_cycles_accept128(cycles)
    }
    fn cycles_available(&self) -> u128 {
        ic_cdk::api::call::msg_cycles_available128()
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
    let env = &KytCanisterEnv;
    match env.config().kyt_mode() {
        KytMode::AcceptAll => CheckTransactionResponse::Passed,
        KytMode::RejectAll => CheckTransactionResponse::Failed(Vec::new()),
        KytMode::Normal => {
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

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    use candid_parser::utils::{
        service_equal,
        CandidSource,
    };

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("btc_kyt_canister.did");

    service_equal(
        CandidSource::Text(dbg!(&new_interface)),
        CandidSource::File(old_interface.as_path()),
    )
    .unwrap();
}
