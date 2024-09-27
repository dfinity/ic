use bitcoin::{consensus::Decodable, Address, Transaction};
use ic_btc_interface::Txid;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::http_request::http_request;

pub mod blocklist;
mod fetch;
mod providers;
mod state;
mod types;

pub use fetch::{
    get_tx_cycle_cost, CHECK_TRANSACTION_CYCLES_REQUIRED, CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
    INITIAL_MAX_RESPONSE_BYTES,
};
use fetch::{FetchEnv, FetchResult, TryFetchResult};
pub use state::{get_config, set_config, Config};
use state::{FetchGuardError, HttpGetTxError};
pub use types::*;

impl From<(Txid, HttpGetTxError)> for CheckTransactionResponse {
    fn from((txid, err): (Txid, HttpGetTxError)) -> CheckTransactionResponse {
        let txid = txid.as_ref().to_vec();
        match err {
            HttpGetTxError::Rejected { message, .. } => {
                CheckTransactionRetriable::TransientInternalError(message).into()
            }
            HttpGetTxError::ResponseTooLarge => {
                (CheckTransactionIrrecoverableError::ResponseTooLarge { txid }).into()
            }
            _ => {
                CheckTransactionIrrecoverableError::InvalidTransaction(format!("{:?}", err)).into()
            }
        }
    }
}

pub fn blocklist_contains(address: &Address) -> bool {
    blocklist::BTC_ADDRESS_BLOCKLIST
        .binary_search(&address.to_string().as_ref())
        .is_ok()
}

pub fn is_response_too_large(code: &RejectionCode, message: &str) -> bool {
    code == &RejectionCode::SysFatal
        && (message.contains("size limit") || message.contains("length limit"))
}

struct KytCanisterEnv;

impl FetchEnv for KytCanisterEnv {
    type FetchGuard = state::FetchGuard;

    fn new_fetch_guard(&self, txid: Txid) -> Result<Self::FetchGuard, FetchGuardError> {
        state::FetchGuard::new(txid)
    }

    async fn http_get_tx(
        &self,
        txid: Txid,
        max_response_bytes: u32,
    ) -> Result<Transaction, HttpGetTxError> {
        // TODO(XC-159): Support multiple providers
        let request = providers::create_request(get_config().btc_network, txid, max_response_bytes);
        let url = request.url.clone();
        let cycles = get_tx_cycle_cost(max_response_bytes);
        match http_request(request, cycles).await {
            Ok((response,)) => {
                // Ensure response is 200 before decoding
                if response.status != 200u32 {
                    let code = if response.status == 429u32 {
                        RejectionCode::SysTransient
                    } else {
                        RejectionCode::SysFatal
                    };
                    return Err(HttpGetTxError::Rejected {
                        code,
                        message: format!("HTTP GET {} received code {}", url, response.status),
                    });
                }
                let tx = Transaction::consensus_decode(&mut response.body.as_slice())
                    .map_err(|err| HttpGetTxError::TxEncoding(err.to_string()))?;
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
    match env.try_fetch_tx(txid) {
        TryFetchResult::Pending => CheckTransactionRetriable::Pending.into(),
        TryFetchResult::HighLoad => CheckTransactionRetriable::HighLoad.into(),
        TryFetchResult::Error(err) => (txid, err).into(),
        TryFetchResult::NotEnoughCycles => CheckTransactionStatus::NotEnoughCycles.into(),
        TryFetchResult::Fetched(fetched) => env.check_fetched(txid, &fetched).await,
        TryFetchResult::ToFetch(do_fetch) => {
            match do_fetch.await {
                Ok(FetchResult::Fetched(fetched)) => env.check_fetched(txid, &fetched).await,
                Ok(FetchResult::Error(err)) => (txid, err).into(),
                Ok(FetchResult::RetryWithBiggerBuffer) => CheckTransactionRetriable::Pending.into(),
                Err(_) => unreachable!(), // should never happen
            }
        }
    }
}

mod test {
    #[test]
    fn blocklist_is_sorted() {
        use crate::blocklist::BTC_ADDRESS_BLOCKLIST;
        for (l, r) in BTC_ADDRESS_BLOCKLIST
            .iter()
            .zip(BTC_ADDRESS_BLOCKLIST.iter().skip(1))
        {
            assert!(l < r, "the block list is not sorted: {} >= {}", l, r);
        }
    }
}
