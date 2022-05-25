use crate::util::candid_error_to_user_error;
use candid::Encode;
use ic_btc_canister::state::State as BitcoinCanisterState;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::{
    BitcoinGetBalanceArgs, BitcoinGetUtxosArgs, BitcoinNetwork, Method as Ic00Method, Payload,
};
use ic_registry_subnet_features::BitcoinFeatureStatus;
use ic_replicated_state::ReplicatedState;

/// Handles a `bitcoin_get_balance` request.
pub fn get_balance(payload: &[u8], state: &mut ReplicatedState) -> Result<Vec<u8>, UserError> {
    verify_feature_is_enabled(state)?;

    match BitcoinGetBalanceArgs::decode(payload) {
        Err(err) => Err(candid_error_to_user_error(err)),
        Ok(args) => {
            if args.network != BitcoinNetwork::Testnet {
                return Err(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    format!(
                        "The {} API supports only the Testnet network.",
                        Ic00Method::BitcoinGetBalance
                    ),
                ));
            }

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
}

/// Handles a `bitcoin_get_utxos` request.
pub fn get_utxos(payload: &[u8], state: &mut ReplicatedState) -> Result<Vec<u8>, UserError> {
    verify_feature_is_enabled(state)?;

    match BitcoinGetUtxosArgs::decode(payload) {
        Err(err) => Err(candid_error_to_user_error(err)),
        Ok(args) => {
            if args.network != BitcoinNetwork::Testnet {
                return Err(UserError::new(
                    ErrorCode::CanisterRejectedMessage,
                    format!(
                        "The {} API supports only the Testnet network.",
                        Ic00Method::BitcoinGetBalance
                    ),
                ));
            }

            let btc_canister_state = BitcoinCanisterState::from(state.take_bitcoin_state());
            let utxos_response =
                ic_btc_canister::get_utxos(&btc_canister_state, &args.address, args.filter);
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
}

fn verify_feature_is_enabled(state: &mut ReplicatedState) -> Result<(), UserError> {
    if state.metadata.own_subnet_features.bitcoin().status != BitcoinFeatureStatus::Enabled {
        return Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            "The bitcoin API is not enabled on this subnet.",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
