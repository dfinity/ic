use bitcoin::{address::FromScriptError, consensus::Decodable, Address, Transaction};
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
    INITIAL_BUFFER_SIZE,
};
use fetch::{FetchEnv, FetchResult, FetchState, TryFetchResult};
use state::{FetchGuardError, FetchTxStatus};
pub use types::*;

#[derive(Debug, Clone)]
pub enum GetTxError {
    Address(FromScriptError),
    Encoding(String),
    TxIdMismatch {
        expected: [u8; 32],
        decoded: [u8; 32],
    },
    ResponseTooLarge,
    Rejected {
        code: RejectionCode,
        message: String,
    },
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

async fn get_tx(tx_id: Txid, buffer_size: u32) -> Result<Transaction, GetTxError> {
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
        max_response_bytes: Some(buffer_size as u64),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: ic_cdk::api::id(),
                method: "transform".to_string(),
            }),
            context: vec![],
        }),
        headers: request_headers,
    };
    let cycles = get_tx_cycle_cost(buffer_size);
    match http_request(request, cycles).await {
        Ok((response,)) => {
            // TODO(XC-158): ensure response is 200 before decoding
            let tx = Transaction::consensus_decode(&mut response.body.as_slice())
                .map_err(|err| GetTxError::Encoding(err.to_string()))?;
            // Verify the correctness of the transaction by recomputing the transaction ID.
            let decoded_tx_id = tx.compute_txid();
            if decoded_tx_id.as_ref() as &[u8; 32] != tx_id.as_ref() {
                return Err(GetTxError::TxIdMismatch {
                    expected: tx_id.into(),
                    decoded: *decoded_tx_id.as_ref(),
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
    async fn get_tx(&self, txid: Txid, buffer_size: u32) -> Result<Transaction, GetTxError> {
        get_tx(txid, buffer_size).await
    }
    fn cycles_accept(&self, cycles: u128) -> u128 {
        ic_cdk::api::call::msg_cycles_accept128(cycles)
    }
    fn cycles_available(&self) -> u128 {
        ic_cdk::api::call::msg_cycles_available128()
    }
}

pub async fn check_transaction_inputs(txid: Txid) -> CheckTransactionResponse {
    let env = &KytCanisterEnv;
    let state = &KytCanisterState;
    match env.try_fetch_tx(state, txid) {
        TryFetchResult::Pending => CheckTransactionResponse::Pending,
        TryFetchResult::HighLoad => CheckTransactionResponse::HighLoad,
        TryFetchResult::Error(msg) => CheckTransactionResponse::Error(format!("{:?}", msg)),
        TryFetchResult::NotEnoughCycles => CheckTransactionResponse::NotEnoughCycles,
        TryFetchResult::Fetched(fetched) => env.check_fetched(state, txid, &fetched).await,
        TryFetchResult::ToFetch(do_fetch) => {
            match do_fetch.await {
                Ok(FetchResult::Fetched(fetched)) => env.check_fetched(state, txid, &fetched).await,
                Ok(FetchResult::Error(err)) => {
                    CheckTransactionResponse::Error(format!("{:?}", err))
                }
                Ok(FetchResult::RetryWithBiggerBuffer) => CheckTransactionResponse::Pending,
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
