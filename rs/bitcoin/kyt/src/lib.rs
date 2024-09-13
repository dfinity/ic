use bitcoin::{consensus::Decodable, Address, Transaction};
use ic_btc_interface::Txid;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::http_request::{
    http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod, TransformContext,
    TransformFunc,
};

pub mod blocklist;
mod fetch;
mod state;
mod types;

pub use fetch::{
    get_tx_cycle_cost, CHECK_TRANSACTION_CYCLES_REQUIRED, CHECK_TRANSACTION_CYCLES_SERVICE_FEE,
    INITIAL_MAX_RESPONSE_BYTES,
};
use fetch::{FetchEnv, FetchResult, FetchState, TryFetchResult};
use state::{FetchGuardError, FetchTxStatus};
pub use types::*;

#[derive(Debug, Clone)]
pub enum GetTxError {
    TxEncoding(String),
    TxidMismatch {
        expected: Txid,
        decoded: Txid,
    },
    ResponseTooLarge,
    Rejected {
        code: RejectionCode,
        message: String,
    },
}

impl From<(Txid, GetTxError)> for CheckTransactionError {
    fn from((txid, err): (Txid, GetTxError)) -> CheckTransactionError {
        let txid = txid.as_ref().to_vec();
        match err {
            GetTxError::TxEncoding(message) => CheckTransactionError::Tx { txid, message },
            GetTxError::TxidMismatch { expected, decoded } => CheckTransactionError::TxidMismatch {
                expected: expected.as_ref().to_vec(),
                decoded: decoded.as_ref().to_vec(),
            },
            GetTxError::Rejected { code, message } => CheckTransactionError::Rejected {
                code: code as u32,
                message,
            },
            GetTxError::ResponseTooLarge => CheckTransactionError::ResponseTooLarge { txid },
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

async fn get_tx(tx_id: Txid, max_response_bytes: u32) -> Result<Transaction, GetTxError> {
    // TODO(XC-159): Support multiple providers
    let host = "btcscan.org";
    let url = format!("https://{}/api/tx/{}/raw", host, tx_id);
    let request_headers = vec![
        HttpHeader {
            name: "Host".to_string(),
            value: format!("{host}:443"),
        },
        HttpHeader {
            name: "User-Agent".to_string(),
            value: "bitcoin_inputs_collector".to_string(),
        },
    ];
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        method: HttpMethod::GET,
        body: None,
        max_response_bytes: Some(max_response_bytes as u64),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: ic_cdk::api::id(),
                method: "transform".to_string(),
            }),
            context: vec![],
        }),
        headers: request_headers,
    };
    let cycles = get_tx_cycle_cost(max_response_bytes);
    match http_request(request, cycles).await {
        Ok((response,)) => {
            // TODO(XC-158): ensure response is 200 before decoding
            let tx = Transaction::consensus_decode(&mut response.body.as_slice())
                .map_err(|err| GetTxError::TxEncoding(err.to_string()))?;
            // Verify the correctness of the transaction by recomputing the transaction ID.
            let decoded_tx_id = tx.compute_txid();
            if decoded_tx_id.as_ref() as &[u8; 32] != tx_id.as_ref() {
                return Err(GetTxError::TxidMismatch {
                    expected: tx_id,
                    decoded: Txid::from(*(decoded_tx_id.as_ref() as &[u8; 32])),
                });
            }
            Ok(tx)
        }
        Err((r, m)) if is_response_too_large(&r, &m) => Err(GetTxError::ResponseTooLarge),
        Err((r, m)) => {
            // TODO(XC-158): maybe try other providers and also log the error.
            println!("The http_request resulted into error. RejectionCode: {r:?}, Error: {m}");
            Err(GetTxError::Rejected {
                code: r,
                message: m,
            })
        }
    }
}

struct KytCanisterState;

impl FetchState for KytCanisterState {
    type FetchGuard = state::FetchGuard;

    fn new_fetch_guard(&self, txid: Txid) -> Result<Self::FetchGuard, FetchGuardError> {
        state::FetchGuard::new(txid)
    }

    fn get_fetch_status(&self, txid: Txid) -> Option<FetchTxStatus> {
        state::get_fetch_status(txid)
    }

    fn set_fetch_status(&self, txid: Txid, status: FetchTxStatus) {
        state::set_fetch_status(txid, status)
    }

    fn set_fetched_address(&self, txid: Txid, index: usize, address: Address) {
        state::set_fetched_address(txid, index, address)
    }
}

struct KytCanisterEnv;

impl FetchEnv for KytCanisterEnv {
    async fn get_tx(&self, txid: Txid, max_response_bytes: u32) -> Result<Transaction, GetTxError> {
        get_tx(txid, max_response_bytes).await
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
pub async fn check_transaction_inputs(
    txid: Txid,
) -> Result<CheckTransactionResponse, CheckTransactionError> {
    let env = &KytCanisterEnv;
    let state = &KytCanisterState;
    match env.try_fetch_tx(state, txid) {
        TryFetchResult::Pending => Ok(CheckTransactionResponse::Pending),
        TryFetchResult::HighLoad => Ok(CheckTransactionResponse::HighLoad),
        TryFetchResult::Error(err) => Err((txid, err).into()),
        TryFetchResult::NotEnoughCycles => Ok(CheckTransactionResponse::NotEnoughCycles),
        TryFetchResult::Fetched(fetched) => env.check_fetched(state, txid, &fetched).await,
        TryFetchResult::ToFetch(do_fetch) => {
            match do_fetch.await {
                Ok(FetchResult::Fetched(fetched)) => env.check_fetched(state, txid, &fetched).await,
                Ok(FetchResult::Error(err)) => Err((txid, err).into()),
                Ok(FetchResult::RetryWithBiggerBuffer) => Ok(CheckTransactionResponse::Pending),
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
