use crate::util::candid_error_to_user_error;
use candid::Encode;
use ic_btc_canister::state::State as BitcoinCanisterState;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::{
    BitcoinGetBalanceArgs, BitcoinGetCurrentFeePercentilesArgs, BitcoinGetSuccessorsArgs,
    BitcoinGetSuccessorsResponse, BitcoinGetUtxosArgs, BitcoinNetwork, BitcoinSendTransactionArgs,
    EmptyBlob, Method as Ic00Method, Payload,
};
use ic_registry_subnet_features::BitcoinFeatureStatus;
use ic_replicated_state::{
    metadata_state::subnet_call_context_manager::BitcoinGetSuccessorsContext, ReplicatedState,
};
use ic_types::{messages::Request, Cycles, PrincipalId};

// A number of last transactions in a block chain to calculate fee percentiles.
// Assumed to be ~10'000 transactions to cover the last ~4-10 blocks.
//
// Note: number of transactions is supposed to be constant, because `get_current_fee_percentiles` cache
// does not support `number_of_transactions` multiple values.
const NUMBER_OF_TRANSACTIONS_FOR_CALCULATING_FEES: u32 = 10_000;

const GET_BALANCE_FEE: Cycles = Cycles::new(100_000_000);
const GET_UTXOS_FEE: Cycles = Cycles::new(100_000_000);
const GET_CURRENT_FEE_PERCENTILES_FEE: Cycles = Cycles::new(100_000_000);
const SEND_TRANSACTION_FEE_BASE: Cycles = Cycles::new(5_000_000_000);
const SEND_TRANSACTION_FEE_PER_BYTE: Cycles = Cycles::new(20_000_000);

/// Handles a `bitcoin_get_balance` request.
pub fn get_balance(
    payload: &[u8],
    state: &mut ReplicatedState,
    payment: Cycles,
) -> (Result<Vec<u8>, UserError>, Cycles) {
    execute_bitcoin_endpoint(
        payload,
        state,
        payment,
        GET_BALANCE_FEE,
        |payload: &[u8], state: &mut ReplicatedState| -> Result<Vec<u8>, UserError> {
            match BitcoinGetBalanceArgs::decode(payload) {
                Err(err) => Err(candid_error_to_user_error(err)),
                Ok(args) => {
                    // Verify that the request is for the expected network.
                    verify_network(args.network.into(), state.bitcoin().network())?;

                    let btc_canister_state = BitcoinCanisterState::from(state.take_bitcoin_state());
                    let balance_response = ic_btc_canister::get_balance(
                        &btc_canister_state,
                        &args.address,
                        args.min_confirmations,
                    );
                    state.put_bitcoin_state(btc_canister_state.into());
                    balance_response
                        .map(|balance|
                    // Using `unwrap()` here is safe because it's a simple u64 conversion.
                    Encode!(&balance).unwrap())
                        .map_err(|err| {
                            UserError::new(
                                ErrorCode::CanisterRejectedMessage,
                                format!("{} failed: {}", Ic00Method::BitcoinGetBalance, err),
                            )
                        })
                }
            }
        },
    )
}

/// Handles a `bitcoin_get_utxos` request.
pub fn get_utxos(
    payload: &[u8],
    state: &mut ReplicatedState,
    payment: Cycles,
) -> (Result<Vec<u8>, UserError>, Cycles) {
    execute_bitcoin_endpoint(
        payload,
        state,
        payment,
        GET_UTXOS_FEE,
        |payload: &[u8], state: &mut ReplicatedState| -> Result<Vec<u8>, UserError> {
            match BitcoinGetUtxosArgs::decode(payload) {
                Err(err) => Err(candid_error_to_user_error(err)),
                Ok(args) => {
                    // Verify that the request is for the expected network.
                    verify_network(args.network.into(), state.bitcoin().network())?;

                    let btc_canister_state = BitcoinCanisterState::from(state.take_bitcoin_state());
                    let utxos_response = ic_btc_canister::get_utxos(
                        &btc_canister_state,
                        &args.address,
                        args.filter.map(|f| f.into()),
                    );
                    state.put_bitcoin_state(btc_canister_state.into());

                    utxos_response
                        .map(|response| Encode!(&response).unwrap())
                        .map_err(|err| {
                            UserError::new(
                                ErrorCode::CanisterRejectedMessage,
                                format!("{} failed: {}", Ic00Method::BitcoinGetUtxos, err),
                            )
                        })
                }
            }
        },
    )
}

/// Handles a `get_current_fee_percentiles` request.
pub fn get_current_fee_percentiles(
    payload: &[u8],
    state: &mut ReplicatedState,
    payment: Cycles,
) -> (Result<Vec<u8>, UserError>, Cycles) {
    execute_bitcoin_endpoint(
        payload,
        state,
        payment,
        GET_CURRENT_FEE_PERCENTILES_FEE,
        |payload: &[u8], state: &mut ReplicatedState| -> Result<Vec<u8>, UserError> {
            match BitcoinGetCurrentFeePercentilesArgs::decode(payload) {
                Err(err) => Err(candid_error_to_user_error(err)),
                Ok(args) => {
                    // Verify that the request is for the expected network.
                    verify_network(args.network.into(), state.bitcoin().network())?;

                    let mut btc_canister_state =
                        BitcoinCanisterState::from(state.take_bitcoin_state());
                    let response = ic_btc_canister::get_current_fee_percentiles(
                        &mut btc_canister_state,
                        NUMBER_OF_TRANSACTIONS_FOR_CALCULATING_FEES,
                    );
                    state.put_bitcoin_state(btc_canister_state.into());

                    Ok(Encode!(&response).unwrap())
                }
            }
        },
    )
}

/// Handles a `bitcoin_send_transaction` request.
pub fn send_transaction(
    payload: &[u8],
    state: &mut ReplicatedState,
    payment: Cycles,
) -> (Result<Vec<u8>, UserError>, Cycles) {
    let args = match BitcoinSendTransactionArgs::decode(payload) {
        Err(err) => {
            // Failed to parse payload. Charge the base fee and return.
            return (
                Err(candid_error_to_user_error(err)),
                payment - SEND_TRANSACTION_FEE_BASE,
            );
        }
        Ok(args) => args,
    };

    let fee =
        SEND_TRANSACTION_FEE_BASE + SEND_TRANSACTION_FEE_PER_BYTE * args.transaction.len() as u64;

    execute_bitcoin_endpoint(
        payload,
        state,
        payment,
        fee,
        move |_payload: &[u8], state: &mut ReplicatedState| -> Result<Vec<u8>, UserError> {
            // Verify that the request is for the expected network.
            verify_network(args.network.into(), state.bitcoin().network())?;

            let mut btc_canister_state = BitcoinCanisterState::from(state.take_bitcoin_state());
            let result = ic_btc_canister::send_transaction(&mut btc_canister_state, args);
            state.put_bitcoin_state(btc_canister_state.into());

            result
                .map_err(|err| {
                    UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        format!("{} failed: {}", Ic00Method::BitcoinSendTransaction, err),
                    )
                })
                .map(|()| EmptyBlob.encode())
        },
    )
}

/// Handles a `bitcoin_get_successors` request.
/// Returns Ok if the request has been accepted, and an error otherwise.
pub fn get_successors(
    bitcoin_canisters: &[PrincipalId],
    request: &Request,
    state: &mut ReplicatedState,
) -> Result<Option<Vec<u8>>, UserError> {
    if !bitcoin_canisters.contains(&request.sender().get()) {
        return Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            String::from("Permission denied."),
        ));
    }

    // Remove follow-up responses for canisters that are no longer considered "bitcoin canisters".
    state
        .metadata
        .bitcoin_get_successors_follow_up_responses
        .retain(|sender, _| bitcoin_canisters.contains(&sender.get()));

    match BitcoinGetSuccessorsArgs::decode(request.method_payload()) {
        Ok(get_successors_request) => {
            match get_successors_request {
                BitcoinGetSuccessorsArgs::Initial(payload) => {
                    // Insert request into subnet call contexts.
                    state
                        .metadata
                        .subnet_call_context_manager
                        .push_bitcoin_get_successors_request(BitcoinGetSuccessorsContext {
                            request: request.clone(),
                            payload,
                        });

                    Ok(None)
                }
                BitcoinGetSuccessorsArgs::FollowUp(follow_up_index) => {
                    match state
                        .metadata
                        .bitcoin_get_successors_follow_up_responses
                        .get(&request.sender())
                    {
                        Some(follow_up_responses) => {
                            match follow_up_responses.get(follow_up_index as usize) {
                                Some(payload) => Ok(Some(
                                    BitcoinGetSuccessorsResponse::FollowUp(payload.to_vec())
                                        .encode(),
                                )),
                                None => Err(UserError::new(
                                    ErrorCode::CanisterRejectedMessage,
                                    "Page not found.",
                                )),
                            }
                        }
                        None => Err(UserError::new(
                            ErrorCode::CanisterRejectedMessage,
                            "Follow up request not found",
                        )),
                    }
                }
            }
        }
        Err(err) => Err(candid_error_to_user_error(err)),
    }
}

fn is_feature_enabled(state: &mut ReplicatedState) -> bool {
    state.metadata.own_subnet_features.bitcoin().status == BitcoinFeatureStatus::Enabled
}

fn verify_network(
    network_argument: BitcoinNetwork,
    network_supported: BitcoinNetwork,
) -> Result<(), UserError> {
    if network_argument != network_supported {
        return Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!(
                "Received request for {} but the subnet supports {}",
                network_argument, network_supported
            ),
        ));
    }

    Ok(())
}

fn execute_bitcoin_endpoint(
    payload: &[u8],
    state: &mut ReplicatedState,
    payment: Cycles,
    fee_to_charge: Cycles,
    endpoint: impl FnOnce(&[u8], &mut ReplicatedState) -> Result<Vec<u8>, UserError>,
) -> (Result<Vec<u8>, UserError>, Cycles) {
    // Verify that the feature is enabled.
    if !is_feature_enabled(state) {
        return (
            Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                "The bitcoin API is not enabled on this subnet.",
            )),
            payment,
        );
    }

    // Verify that payment has been received.
    if payment < fee_to_charge {
        return (
            Err(UserError::new(
                ErrorCode::CanisterRejectedMessage,
                format!(
                    "Received {} cycles. {} cycles are required.",
                    payment, fee_to_charge
                ),
            )),
            payment,
        );
    }

    // Execute the endpoint and deduct the fee.
    (endpoint(payload, state), payment - fee_to_charge)
}

#[cfg(test)]
mod tests;
