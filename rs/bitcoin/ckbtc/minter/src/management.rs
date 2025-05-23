//! This module contains async functions for interacting with the management canister.
use crate::logs::P0;
use crate::metrics::{observe_get_utxos_latency, observe_sign_with_ecdsa_latency};
use crate::{tx, CanisterRuntime, ECDSAPublicKey, GetUtxosRequest, GetUtxosResponse, Network};
use candid::{CandidType, Principal};
use ic_btc_checker::{
    CheckAddressArgs, CheckAddressResponse, CheckTransactionArgs, CheckTransactionResponse,
};
use ic_btc_interface::{Address, MillisatoshiPerByte, Utxo};
use ic_canister_log::log;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::management_canister::bitcoin::UtxoFilter;
use ic_management_canister_types::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, EcdsaPublicKeyResult,
};
use ic_management_canister_types_private::DerivationPath;
use serde::de::DeserializeOwned;
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

    pub fn from_cdk_error(method: &str, (code, msg): (RejectionCode, String)) -> CallError {
        CallError {
            method: String::from(method),
            reason: Reason::from_reject(code, msg),
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
            Self::CanisterError(msg) => write!(fmt, "canister error: {}", msg),
            Self::Rejected(msg) => {
                write!(fmt, "the management canister rejected the call: {}", msg)
            }
        }
    }
}

impl Reason {
    fn from_reject(reject_code: RejectionCode, reject_message: String) -> Self {
        match reject_code {
            RejectionCode::SysTransient => Self::QueueIsFull,
            RejectionCode::CanisterError => Self::CanisterError(reject_message),
            RejectionCode::CanisterReject => Self::Rejected(reject_message),
            _ => Self::QueueIsFull,
        }
    }
}

pub(crate) async fn call<I, O>(method: &str, payment: u64, input: &I) -> Result<O, CallError>
where
    I: CandidType,
    O: CandidType + DeserializeOwned,
{
    let balance = ic_cdk::api::canister_balance128();
    if balance < payment as u128 {
        log!(
            P0,
            "Failed to call {}: need {} cycles, the balance is only {}",
            method,
            payment,
            balance
        );

        return Err(CallError {
            method: method.to_string(),
            reason: Reason::OutOfCycles,
        });
    }

    let res: Result<(O,), _> = ic_cdk::api::call::call_with_payment(
        Principal::management_canister(),
        method,
        (input,),
        payment,
    )
    .await;

    match res {
        Ok((output,)) => Ok(output),
        Err((code, msg)) => Err(CallError {
            method: method.to_string(),
            reason: Reason::from_reject(code, msg),
        }),
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
            runtime.bitcoin_get_utxos(req.clone()).await.inspect(|res| {
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
        filter: Some(UtxoFilter::MinConfirmations(min_confirmations)),
    };

    let mut response = bitcoin_get_utxos(&mut now, request.clone(), source, runtime).await?;

    let mut utxos = std::mem::take(&mut response.utxos);
    let mut num_pages: usize = 1;

    // Continue fetching until there are no more pages.
    while let Some(page) = response.next_page {
        let paged_request = GetUtxosRequest {
            filter: Some(UtxoFilter::Page(page.to_vec())),
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
pub async fn bitcoin_get_utxos(request: GetUtxosRequest) -> Result<GetUtxosResponse, CallError> {
    ic_cdk::api::management_canister::bitcoin::bitcoin_get_utxos(request)
        .await
        .map(|(response,)| response.into())
        .map_err(|err| CallError::from_cdk_error("bitcoin_get_utxos", err))
}

/// Returns the current fee percentiles on the Bitcoin network.
pub async fn get_current_fees(network: Network) -> Result<Vec<MillisatoshiPerByte>, CallError> {
    ic_cdk::api::management_canister::bitcoin::bitcoin_get_current_fee_percentiles(
        ic_cdk::api::management_canister::bitcoin::GetCurrentFeePercentilesRequest {
            network: network.into(),
        },
    )
    .await
    .map(|(result,)| result)
    .map_err(|err| CallError::from_cdk_error("bitcoin_get_current_fee_percentiles", err))
}

/// Sends the transaction to the network the management canister interacts with.
pub async fn send_transaction(
    transaction: &tx::SignedTransaction,
    network: Network,
) -> Result<(), CallError> {
    ic_cdk::api::management_canister::bitcoin::bitcoin_send_transaction(
        ic_cdk::api::management_canister::bitcoin::SendTransactionRequest {
            transaction: transaction.serialize(),
            network: network.into(),
        },
    )
    .await
    .map_err(|err| CallError::from_cdk_error("bitcoin_send_transaction", err))
}

/// Fetches the ECDSA public key of the canister.
pub async fn ecdsa_public_key(
    key_name: String,
    derivation_path: DerivationPath,
) -> Result<ECDSAPublicKey, CallError> {
    // Retrieve the public key of this canister at the given derivation path
    // from the ECDSA API.
    call(
        "ecdsa_public_key",
        /*payment=*/ 0,
        &EcdsaPublicKeyArgs {
            canister_id: None,
            derivation_path: derivation_path.into_inner(),
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name,
            },
        },
    )
    .await
    .map(|response: EcdsaPublicKeyResult| ECDSAPublicKey {
        public_key: response.public_key,
        chain_code: response.chain_code,
    })
}

/// Signs a message hash using the tECDSA API.
pub async fn sign_with_ecdsa<R: CanisterRuntime>(
    key_name: String,
    derivation_path: DerivationPath,
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

/// Check if the given Bitcoin address is blocked.
pub async fn check_withdrawal_destination_address(
    btc_checker_principal: Principal,
    address: String,
) -> Result<CheckAddressResponse, CallError> {
    let (res,): (CheckAddressResponse,) = ic_cdk::api::call::call(
        btc_checker_principal,
        "check_address",
        (CheckAddressArgs { address },),
    )
    .await
    .map_err(|(code, message)| CallError {
        method: "check_address".to_string(),
        reason: Reason::from_reject(code, message),
    })?;
    Ok(res)
}

/// Check if the given UTXO passes Bitcoin check.
pub async fn check_transaction(
    btc_checker_principal: Principal,
    utxo: &Utxo,
    cycle_payment: u128,
) -> Result<CheckTransactionResponse, CallError> {
    let (res,): (CheckTransactionResponse,) = ic_cdk::api::call::call_with_payment128(
        btc_checker_principal,
        "check_transaction",
        (CheckTransactionArgs {
            txid: utxo.outpoint.txid.as_ref().to_vec(),
        },),
        cycle_payment,
    )
    .await
    .map_err(|(code, message)| CallError {
        method: "check_transaction".to_string(),
        reason: Reason::from_reject(code, message),
    })?;
    Ok(res)
}
