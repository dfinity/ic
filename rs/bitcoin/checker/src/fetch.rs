use crate::logs::WARN;
use crate::state::{
    FetchGuardError, FetchTxStatus, FetchTxStatusError, FetchedTx, HttpGetTxError,
    TransactionCheckData,
};
use crate::{Config, providers, state};
use bitcoin::Transaction;
use futures::future::try_join_all;
use ic_btc_checker::{
    CheckTransactionIrrecoverableError, CheckTransactionQueryResponse, CheckTransactionResponse,
    CheckTransactionRetriable, CheckTransactionStatus, INITIAL_MAX_RESPONSE_BYTES,
    RETRY_MAX_RESPONSE_BYTES, blocklist::is_blocked, get_tx_cycle_cost,
};
use ic_btc_interface::Txid;
use ic_canister_log::log;
use std::convert::Infallible;

#[cfg(test)]
mod tests;

impl HttpGetTxError {
    pub(crate) fn into_response(self, txid: Txid) -> CheckTransactionResponse {
        let txid = txid.as_ref().to_vec();
        match self {
            HttpGetTxError::Rejected { message, .. } => {
                CheckTransactionRetriable::TransientInternalError(message).into()
            }
            HttpGetTxError::ResponseTooLarge => {
                (CheckTransactionIrrecoverableError::ResponseTooLarge { txid }).into()
            }
            _ => CheckTransactionRetriable::TransientInternalError(self.to_string()).into(),
        }
    }
}

pub enum FetchResult {
    RetryWithBiggerBuffer,
    Error(HttpGetTxError),
    Fetched(FetchedTx),
}

pub enum TryFetchResult<F> {
    Pending,
    HighLoad,
    NotEnoughCycles,
    Fetched(FetchedTx),
    ToFetch(F),
}

/// Trait that abstracts over system functions like fetching transaction, calcuating cycles, etc.
pub trait FetchEnv {
    type FetchGuard;
    fn new_fetch_guard(&self, txid: Txid) -> Result<Self::FetchGuard, FetchGuardError>;
    fn config(&self) -> Config;

    async fn http_get_tx(
        &self,
        provider: &providers::Provider,
        txid: Txid,
        max_response_bytes: u32,
    ) -> Result<Transaction, HttpGetTxError>;
    fn cycles_accept(&self, cycles: u128) -> u128;

    /// Try to fetch a transaction given its txid:
    /// - If it is already available, return `Fetched`.
    /// - If it is already pending, return `Pending`.
    /// - If it is pending retry or not found, return a future that calls `fetch_tx`.
    /// - Or return other conditions like `HighLoad` or `Error`.
    fn try_fetch_tx(
        &self,
        txid: Txid,
    ) -> TryFetchResult<impl futures::Future<Output = Result<FetchResult, Infallible>>> {
        let (provider, max_response_bytes) = match state::get_fetch_status(txid) {
            None => (
                providers::next_provider(self.config().btc_network()),
                INITIAL_MAX_RESPONSE_BYTES,
            ),
            Some(FetchTxStatus::PendingRetry {
                max_response_bytes, ..
            }) => (
                providers::next_provider(self.config().btc_network()),
                max_response_bytes,
            ),
            Some(FetchTxStatus::PendingOutcall) => return TryFetchResult::Pending,
            Some(FetchTxStatus::Error(err)) => (
                // An FetchTxStatus error can be retried with another provider
                err.provider.next(),
                // The next provider can use the same max_response_bytes
                err.max_response_bytes,
            ),
            Some(FetchTxStatus::Fetched(fetched)) => return TryFetchResult::Fetched(fetched),
        };
        let guard = match self.new_fetch_guard(txid) {
            Ok(guard) => guard,
            Err(_) => return TryFetchResult::HighLoad,
        };
        let num_subnet_nodes = self.config().num_subnet_nodes;
        let cycle_cost = get_tx_cycle_cost(max_response_bytes, num_subnet_nodes);
        if self.cycles_accept(cycle_cost) < cycle_cost {
            TryFetchResult::NotEnoughCycles
        } else {
            TryFetchResult::ToFetch(self.fetch_tx(guard, provider, txid, max_response_bytes))
        }
    }

    /// Fetch a transaction using http outcall by its txid and set its status to:
    /// - `Fetched`, if it is available.
    /// - `PendingRetry`, if the allocated buffer for outcall wasn't enough.
    /// - `Error`, if an irrecoverable error happened during the outcall of `http_get_tx`.
    ///
    /// Return the correponding `FetchResult`.
    ///
    /// Note that this function does not return any error, but due to requirements
    /// of `try_join_all` it must return a `Result` type.
    async fn fetch_tx(
        &self,
        _guard: Self::FetchGuard,
        provider: providers::Provider,
        txid: Txid,
        max_response_bytes: u32,
    ) -> Result<FetchResult, Infallible> {
        match self.http_get_tx(&provider, txid, max_response_bytes).await {
            Ok(tx) => {
                let input_addresses = tx.input.iter().map(|_| None).collect();
                match TransactionCheckData::from_transaction(provider.btc_network(), tx.clone()) {
                    Ok(tx) => {
                        let fetched = FetchedTx {
                            tx,
                            input_addresses,
                        };
                        state::set_fetch_status(txid, FetchTxStatus::Fetched(fetched.clone()));
                        Ok(FetchResult::Fetched(fetched))
                    }
                    Err(err) => {
                        let err = HttpGetTxError::TxEncoding(err.to_string());
                        state::set_fetch_status(
                            txid,
                            FetchTxStatus::Error(FetchTxStatusError {
                                provider,
                                max_response_bytes,
                                error: err.clone(),
                            }),
                        );
                        Ok(FetchResult::Error(err))
                    }
                }
            }
            Err(HttpGetTxError::ResponseTooLarge)
                if max_response_bytes < RETRY_MAX_RESPONSE_BYTES =>
            {
                state::set_fetch_status(
                    txid,
                    FetchTxStatus::PendingRetry {
                        max_response_bytes: RETRY_MAX_RESPONSE_BYTES,
                    },
                );
                Ok(FetchResult::RetryWithBiggerBuffer)
            }
            Err(err) => {
                state::set_fetch_status(
                    txid,
                    FetchTxStatus::Error(FetchTxStatusError {
                        provider,
                        max_response_bytes,
                        error: err.clone(),
                    }),
                );
                Ok(FetchResult::Error(err))
            }
        }
    }

    /// After a transaction is successfully fetched, we still need to fetch
    /// all of its inputs in order to calculate input addresses. The steps
    /// are described as follows:
    /// - Fetch more if there are transaction inputs to be fetched and checked.
    /// - When they are done, calculate input addresses and record them.
    /// - For those failed due to insufficient outcall response buffer, mark their status
    ///   as `PendingRetry`.
    /// - If we are short of cycles and couldn't fetch all inputs, return `NotEnoughCycles`.
    /// - When all inputs are fetched, compute their addresses and return `Passed`
    ///   if all of them pass the check. Otherwise return `Failed`.
    ///
    /// Pre-condition: `txid` already exists in state with a `Fetched` status.
    async fn check_fetched(&self, txid: Txid, fetched: &FetchedTx) -> CheckTransactionResponse {
        match check_for_blocked_input_addresses(fetched) {
            // If some input addresses are missing, try to fetch them and try again.
            Err(CheckTxInputsError::MissingInputAddresses) => (),
            result => return result.into(),
        }

        let mut futures = vec![];
        let mut jobs = vec![];
        let mut high_load = false;
        let mut not_enough_cycles = false;
        for (index, input) in fetched.tx.inputs.iter().enumerate() {
            if fetched.input_addresses[index].is_none() {
                use TryFetchResult::*;
                match self.try_fetch_tx(input.txid) {
                    ToFetch(do_fetch) => {
                        jobs.push((index, input.txid, input.vout));
                        futures.push(do_fetch)
                    }
                    Fetched(fetched) => {
                        if let Some(address) = &fetched.tx.outputs[input.vout as usize] {
                            state::set_fetched_address(txid, index, address.clone());
                        } else {
                            // This error shouldn't happen unless blockdata is corrupted.
                            let msg = format!(
                                "Tx {} vout {} has no address, but is vin {} of tx {}",
                                input.txid, input.vout, index, txid
                            );
                            log!(WARN, "{msg}");
                            return CheckTransactionIrrecoverableError::InvalidTransaction(msg)
                                .into();
                        }
                    }
                    Pending => {}
                    HighLoad => {
                        high_load = true;
                    }
                    NotEnoughCycles => {
                        not_enough_cycles = true;
                    }
                }
            }
        }

        if futures.is_empty() {
            if not_enough_cycles {
                return CheckTransactionStatus::NotEnoughCycles.into();
            }
            if high_load {
                return CheckTransactionRetriable::HighLoad.into();
            }
        }

        let fetch_results = try_join_all(futures)
            .await
            .unwrap_or_else(|err| unreachable!("error in try_join_all {:?}", err));

        let mut error = None;
        for (i, result) in fetch_results.into_iter().enumerate() {
            let (index, input_txid, vout) = jobs[i];
            match result {
                FetchResult::Fetched(fetched) => {
                    if let Some(address) = &fetched.tx.outputs[vout as usize] {
                        state::set_fetched_address(txid, index, address.clone());
                    } else {
                        // This error shouldn't happen unless blockdata is corrupted.
                        let msg = format!(
                            "Tx {input_txid} vout {vout} has no address, but is vin {index} of tx {txid}"
                        );
                        log!(WARN, "{msg}");
                        error = Some(
                            CheckTransactionIrrecoverableError::InvalidTransaction(msg).into(),
                        );
                    }
                }
                FetchResult::Error(err) => error = Some(err.into_response(input_txid)),
                FetchResult::RetryWithBiggerBuffer => (),
            }
        }
        if let Some(err) = error {
            return err;
        }
        // Check again to see if we have completed
        if let Some(FetchTxStatus::Fetched(fetched)) = state::get_fetch_status(txid) {
            check_for_blocked_input_addresses(&fetched).into()
        } else {
            CheckTransactionRetriable::Pending.into()
        }
    }
}

#[derive(Debug, Clone)]
pub enum CheckTxInputsError {
    MissingInputAddresses,
    BlockedInputAddresses(Vec<String>),
}

impl From<CheckTxInputsError> for CheckTransactionResponse {
    fn from(error: CheckTxInputsError) -> Self {
        match error {
            CheckTxInputsError::MissingInputAddresses => CheckTransactionRetriable::Pending.into(),
            CheckTxInputsError::BlockedInputAddresses(blocked) => {
                CheckTransactionResponse::Failed(blocked)
            }
        }
    }
}

impl From<CheckTxInputsError> for CheckTransactionQueryResponse {
    fn from(error: CheckTxInputsError) -> Self {
        match error {
            CheckTxInputsError::MissingInputAddresses => CheckTransactionQueryResponse::Unknown,
            CheckTxInputsError::BlockedInputAddresses(blocked) => {
                CheckTransactionQueryResponse::Failed(blocked)
            }
        }
    }
}

/// Return `Ok` if no input address is blocked, and an `Err` if either one of the input
/// addresses is blocked, or one of the input addresses is not available.
pub fn check_for_blocked_input_addresses(fetched: &FetchedTx) -> Result<(), CheckTxInputsError> {
    if fetched.input_addresses.iter().any(|x| x.is_none()) {
        return Err(CheckTxInputsError::MissingInputAddresses);
    }
    let blocked: Vec<String> = fetched
        .input_addresses
        .iter()
        .flatten()
        .filter(|address| is_blocked(address))
        .map(|address| address.to_string())
        .collect();
    if blocked.is_empty() {
        Ok(())
    } else {
        Err(CheckTxInputsError::BlockedInputAddresses(blocked))
    }
}
