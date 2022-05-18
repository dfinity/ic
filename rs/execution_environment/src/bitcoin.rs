use crate::util::candid_error_to_user_error;
use candid::Encode;
use ic_btc_canister::state::State as BitcoinCanisterState;
use ic_btc_types::GetBalanceRequest;
use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::{BitcoinGetBalanceArgs, BitcoinNetwork, Method as Ic00Method, Payload};
use ic_registry_subnet_features::BitcoinFeature;
use ic_replicated_state::ReplicatedState;

/// Handles a `bitcoin_get_balance` request.
pub fn get_balance(payload: &[u8], state: &mut ReplicatedState) -> Result<Vec<u8>, UserError> {
    if state.metadata.own_subnet_features.bitcoin_testnet() != BitcoinFeature::Enabled {
        return Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            format!(
                "The {} API is not enabled on this subnet.",
                Ic00Method::BitcoinGetBalance
            ),
        ));
    }

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
                GetBalanceRequest {
                    address: args.address,
                    min_confirmations: args.min_confirmations,
                },
            );
            state.put_bitcoin_state(btc_canister_state.into());
            balance_response
                .map(|balance|
                    // Using `unwrap()` here is safe because of a simple candid::Nat(u64) type.
                    Encode!(&candid::Nat::from(balance)).unwrap())
                .map_err(|err| {
                    UserError::new(
                        ErrorCode::CanisterRejectedMessage,
                        format!("{} failed: {}", Ic00Method::BitcoinGetBalance, err),
                    )
                })
        }
    }
}

#[cfg(test)]
mod tests;
