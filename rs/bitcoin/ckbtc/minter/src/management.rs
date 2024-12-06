//! This module contains async functions for interacting with the management canister.
use crate::logs::P0;
use crate::ECDSAPublicKey;
use crate::{tx, CanisterRuntime};
use candid::{CandidType, Principal};
use ic_btc_checker::{
    CheckAddressArgs, CheckAddressResponse, CheckTransactionArgs, CheckTransactionResponse,
};
use ic_btc_interface::{
    Address, GetUtxosRequest, GetUtxosResponse, MillisatoshiPerByte, Network, OutPoint, Txid, Utxo,
    UtxosFilterInRequest,
};
use ic_canister_log::log;
use ic_cdk::api::{
    call::RejectionCode,
    management_canister::bitcoin::{BitcoinNetwork, UtxoFilter},
};
use ic_management_canister_types::{
    DerivationPath, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId,
};
use serde::de::DeserializeOwned;
use serde_bytes::ByteBuf;
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

#[derive(Copy, Clone)]
pub enum CallSource {
    /// The client initiated the call.
    Client,
    /// The minter initiated the call for internal bookkeeping.
    Minter,
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
        req: GetUtxosRequest,
        source: CallSource,
        runtime: &R,
    ) -> Result<GetUtxosResponse, CallError> {
        match source {
            CallSource::Client => &crate::metrics::GET_UTXOS_CLIENT_CALLS,
            CallSource::Minter => &crate::metrics::GET_UTXOS_MINTER_CALLS,
        }
        .with(|cell| cell.set(cell.get() + 1));
        runtime.bitcoin_get_utxos(req).await
    }

    let mut response = bitcoin_get_utxos(
        GetUtxosRequest {
            address: address.to_string(),
            network: network.into(),
            filter: Some(UtxosFilterInRequest::MinConfirmations(min_confirmations)),
        },
        source,
        runtime,
    )
    .await?;

    let mut utxos = std::mem::take(&mut response.utxos);

    // Continue fetching until there are no more pages.
    while let Some(page) = response.next_page {
        response = bitcoin_get_utxos(
            GetUtxosRequest {
                address: address.to_string(),
                network: network.into(),
                filter: Some(UtxosFilterInRequest::Page(page)),
            },
            source,
            runtime,
        )
        .await?;

        utxos.append(&mut response.utxos);
    }

    response.utxos = utxos;

    Ok(response)
}

/// Fetches a subset of UTXOs for the specified address.
pub async fn bitcoin_get_utxos(request: GetUtxosRequest) -> Result<GetUtxosResponse, CallError> {
    fn cdk_get_utxos_request(
        request: GetUtxosRequest,
    ) -> ic_cdk::api::management_canister::bitcoin::GetUtxosRequest {
        ic_cdk::api::management_canister::bitcoin::GetUtxosRequest {
            address: request.address,
            network: cdk_network(request.network.into()),
            filter: request.filter.map(|filter| match filter {
                UtxosFilterInRequest::MinConfirmations(confirmations)
                | UtxosFilterInRequest::min_confirmations(confirmations) => {
                    UtxoFilter::MinConfirmations(confirmations)
                }
                UtxosFilterInRequest::Page(bytes) | UtxosFilterInRequest::page(bytes) => {
                    UtxoFilter::Page(bytes.into_vec())
                }
            }),
        }
    }

    fn parse_cdk_get_utxos_response(
        response: ic_cdk::api::management_canister::bitcoin::GetUtxosResponse,
    ) -> GetUtxosResponse {
        GetUtxosResponse {
            utxos: response
                .utxos
                .into_iter()
                .map(|utxo| Utxo {
                    outpoint: OutPoint {
                        txid: Txid::try_from(utxo.outpoint.txid.as_slice())
                            .unwrap_or_else(|_| panic!("Unable to parse TXID")),
                        vout: utxo.outpoint.vout,
                    },
                    value: utxo.value,
                    height: utxo.height,
                })
                .collect(),
            tip_block_hash: response.tip_block_hash,
            tip_height: response.tip_height,
            next_page: response.next_page.map(ByteBuf::from),
        }
    }

    ic_cdk::api::management_canister::bitcoin::bitcoin_get_utxos(cdk_get_utxos_request(request))
        .await
        .map(|(response,)| parse_cdk_get_utxos_response(response))
        .map_err(|err| CallError::from_cdk_error("bitcoin_get_utxos", err))
}

/// Returns the current fee percentiles on the Bitcoin network.
pub async fn get_current_fees(network: Network) -> Result<Vec<MillisatoshiPerByte>, CallError> {
    ic_cdk::api::management_canister::bitcoin::bitcoin_get_current_fee_percentiles(
        ic_cdk::api::management_canister::bitcoin::GetCurrentFeePercentilesRequest {
            network: cdk_network(network),
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
            network: cdk_network(network),
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
        &ECDSAPublicKeyArgs {
            canister_id: None,
            derivation_path,
            key_id: EcdsaKeyId {
                curve: EcdsaCurve::Secp256k1,
                name: key_name,
            },
        },
    )
    .await
    .map(|response: ECDSAPublicKeyResponse| ECDSAPublicKey {
        public_key: response.public_key,
        chain_code: response.chain_code,
    })
}

/// Signs a message hash using the tECDSA API.
pub async fn sign_with_ecdsa(
    key_name: String,
    derivation_path: DerivationPath,
    message_hash: [u8; 32],
) -> Result<Vec<u8>, CallError> {
    use ic_cdk::api::management_canister::ecdsa::{
        sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, SignWithEcdsaArgument,
    };

    let result = sign_with_ecdsa(SignWithEcdsaArgument {
        message_hash: message_hash.to_vec(),
        derivation_path: derivation_path.into_inner(),
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name.clone(),
        },
    })
    .await;

    match result {
        Ok((reply,)) => Ok(reply.signature),
        Err((code, msg)) => Err(CallError {
            method: "sign_with_ecdsa".to_string(),
            reason: Reason::from_reject(code, msg),
        }),
    }
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

fn cdk_network(network: Network) -> BitcoinNetwork {
    match network {
        Network::Mainnet => BitcoinNetwork::Mainnet,
        Network::Testnet => BitcoinNetwork::Testnet,
        Network::Regtest => BitcoinNetwork::Regtest,
    }
}
