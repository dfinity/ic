//! This module contains async functions for interacting with the management canister.
use crate::metrics::{observe_get_utxos_latency, observe_sign_with_ecdsa_latency};
use crate::{CanisterRuntime, ECDSAPublicKey, GetUtxosRequest, GetUtxosResponse, Network, tx};
use candid::Principal;
use ic_btc_checker::{CheckTransactionArgs, CheckTransactionResponse};
use ic_btc_interface::{Address, MillisatoshiPerByte, Utxo};
use ic_cdk::bitcoin_canister;
use ic_cdk::bitcoin_canister::GetCurrentFeePercentilesRequest;
use ic_cdk::management_canister::SignCallError;
use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId};
use ic_management_canister_types_private::DerivationPath;
use std::fmt;

/// Represents an error from a management canister call, such as
/// `sign_with_ecdsa` or `bitcoin_send_transaction`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CallError {
    method: String,
    reason: Reason,
}

impl CallError {
    /// Returns the name of the method that resulted in this error.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the failure reason.
    pub fn reason(&self) -> &Reason {
        &self.reason
    }

    pub fn from_cdk_call_error<T: Into<ic_cdk::call::Error>>(method: &str, error: T) -> CallError {
        use ic_cdk::call::Error as CdkError;
        CallError {
            method: String::from(method),
            reason: match error.into() {
                CdkError::InsufficientLiquidCycleBalance(_e) => Reason::OutOfCycles,
                CdkError::CallPerformFailed(e) => Reason::Rejected(e.to_string()),
                CdkError::CallRejected(e) => Reason::Rejected(e.to_string()),
                CdkError::CandidDecodeFailed(e) => Reason::CanisterError(e.to_string()),
            },
        }
    }

    pub fn from_sign_error(error: SignCallError) -> Self {
        let reason = match error {
            SignCallError::SignCostError(e) => {
                //no signatures were made
                Reason::Rejected(e.to_string())
            }
            SignCallError::CallFailed(e) => {
                //no signatures were made
                Reason::Rejected(e.to_string())
            }
            SignCallError::CandidDecodeFailed(e) => Reason::CanisterError(e.to_string()),
        };
        Self {
            method: "sign_with_ecdsa".to_string(),
            reason,
        }
    }
}

impl fmt::Display for CallError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            fmt,
            "management call '{}' failed: {}",
            self.method, self.reason
        )
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
/// The reason for the management call failure.
pub enum Reason {
    /// Failed to send a signature request because the local output queue is
    /// full.
    QueueIsFull,
    /// The canister does not have enough cycles to submit the request.
    OutOfCycles,
    /// The call failed with an error.
    CanisterError(String),
    /// The management canister rejected the signature request (not enough
    /// cycles, the ECDSA subnet is overloaded, etc.).
    Rejected(String),
}

impl fmt::Display for Reason {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueIsFull => write!(fmt, "the canister queue is full"),
            Self::OutOfCycles => write!(fmt, "the canister is out of cycles"),
            Self::CanisterError(msg) => write!(fmt, "canister error: {msg}"),
            Self::Rejected(msg) => {
                write!(fmt, "the management canister rejected the call: {msg}")
            }
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CallSource {
    /// The client initiated the call.
    Client,
    /// The minter initiated the call for internal bookkeeping.
    Minter,
}

impl fmt::Display for CallSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Client => write!(f, "client"),
            Self::Minter => write!(f, "minter"),
        }
    }
}

/// Fetches the full list of UTXOs for the specified address.
pub async fn get_utxos<R: CanisterRuntime>(
    network: Network,
    address: &Address,
    min_confirmations: u32,
    source: CallSource,
    runtime: &R,
) -> Result<GetUtxosResponse, CallError> {
    async fn bitcoin_get_utxos<R: CanisterRuntime>(
        now: &mut u64,
        req: GetUtxosRequest,
        source: CallSource,
        runtime: &R,
    ) -> Result<GetUtxosResponse, CallError> {
        match source {
            CallSource::Client => &crate::metrics::GET_UTXOS_CLIENT_CALLS,
            CallSource::Minter => &crate::metrics::GET_UTXOS_MINTER_CALLS,
        }
        .with(|cell| cell.set(cell.get() + 1));
        if let Some(res) = crate::state::read_state(|s| s.get_utxos_cache.get(&req, *now).cloned())
        {
            crate::metrics::GET_UTXOS_CACHE_HITS.with(|cell| cell.set(cell.get() + 1));
            Ok(res)
        } else {
            crate::metrics::GET_UTXOS_CACHE_MISSES.with(|cell| cell.set(cell.get() + 1));
            runtime.get_utxos(&req).await.inspect(|res| {
                *now = runtime.time();
                crate::state::mutate_state(|s| s.get_utxos_cache.insert(req, res.clone(), *now))
            })
        }
    }

    let start_time = runtime.time();
    let mut now = start_time;
    let request = GetUtxosRequest {
        address: address.clone(),
        network: network.into(),
        filter: Some(bitcoin_canister::UtxosFilter::MinConfirmations(
            min_confirmations,
        )),
    };

    let mut response = bitcoin_get_utxos(&mut now, request.clone(), source, runtime).await?;

    let mut utxos = std::mem::take(&mut response.utxos);
    let mut num_pages: usize = 1;

    // Continue fetching until there are no more pages.
    while let Some(page) = response.next_page {
        let paged_request = GetUtxosRequest {
            filter: Some(bitcoin_canister::UtxosFilter::Page(page.to_vec())),
            ..request.clone()
        };
        response = bitcoin_get_utxos(&mut now, paged_request, source, runtime).await?;
        utxos.append(&mut response.utxos);
        num_pages += 1;
    }

    observe_get_utxos_latency(utxos.len(), num_pages, source, start_time, now);

    response.utxos = utxos;

    Ok(response)
}

/// Fetches a subset of UTXOs for the specified address.
pub async fn bitcoin_get_utxos(request: &GetUtxosRequest) -> Result<GetUtxosResponse, CallError> {
    bitcoin_canister::bitcoin_get_utxos(request)
        .await
        .map(GetUtxosResponse::from)
        .map_err(|err| CallError::from_cdk_call_error("bitcoin_get_utxos", err))
}

/// Returns the current fee percentiles on the Bitcoin network.
pub async fn bitcoin_get_current_fee_percentiles(
    request: &GetCurrentFeePercentilesRequest,
) -> Result<Vec<MillisatoshiPerByte>, CallError> {
    bitcoin_canister::bitcoin_get_current_fee_percentiles(request)
        .await
        .map_err(|err| CallError::from_cdk_call_error("bitcoin_get_current_fee_percentiles", err))
}

/// Sends the transaction to the network the management canister interacts with.
pub async fn send_transaction(
    transaction: &tx::SignedTransaction,
    network: Network,
) -> Result<(), CallError> {
    bitcoin_canister::bitcoin_send_transaction(&bitcoin_canister::SendTransactionRequest {
        transaction: transaction.serialize(),
        network: network.into(),
    })
    .await
    .map_err(|err| CallError::from_cdk_call_error("bitcoin_send_transaction", err))
}

/// Fetches the ECDSA public key of the canister.
pub async fn ecdsa_public_key(
    key_name: String,
    derivation_path: DerivationPath,
) -> Result<ECDSAPublicKey, CallError> {
    ic_cdk::management_canister::ecdsa_public_key(
        &ic_cdk::management_canister::EcdsaPublicKeyArgs {
            canister_id: None,
            derivation_path: derivation_path.into_inner(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name,
            },
        },
    )
    .await
    .map(|response| ECDSAPublicKey {
        public_key: response.public_key,
        chain_code: response.chain_code,
    })
    .map_err(|err| CallError::from_cdk_call_error("ecdsa_public_key", err))
}

/// Signs a message hash using the tECDSA API.
pub async fn sign_with_ecdsa<R: CanisterRuntime>(
    key_name: String,
    derivation_path: Vec<Vec<u8>>,
    message_hash: [u8; 32],
    runtime: &R,
) -> Result<Vec<u8>, CallError> {
    let start_time = runtime.time();

    let result = runtime
        .sign_with_ecdsa(key_name, derivation_path, message_hash)
        .await;

    observe_sign_with_ecdsa_latency(&result, start_time, runtime.time());

    result
}

/// Check if the given UTXO passes Bitcoin check.
pub async fn check_transaction(
    btc_checker_principal: Principal,
    utxo: &Utxo,
    cycle_payment: u128,
) -> Result<CheckTransactionResponse, CallError> {
    // use unbounded wait because calls require cycles
    // and currently cycles are not reimbursed with bounded-wait calls in case of a timeout.
    ic_cdk::call::Call::unbounded_wait(btc_checker_principal, "check_transaction")
        .with_arg(CheckTransactionArgs {
            txid: utxo.outpoint.txid.as_ref().to_vec(),
        })
        .with_cycles(cycle_payment)
        .await
        .map_err(|e| CallError::from_cdk_call_error("check_transaction", e))?
        .candid()
        .map_err(|e| CallError::from_cdk_call_error("check_transaction", e))
}
