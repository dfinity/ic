use crate::{
    agent::BitcoinAgent, canister_common::BitcoinCanister,
    types::from_bitcoin_network_to_ic_btc_types_network, types::UtxosResult, AddressNotTracked,
    BalanceUpdate, MinConfirmationsTooHigh, Satoshi, Utxo, UtxosUpdate, STABILITY_THRESHOLD,
};
use bitcoin::{Address, Network};
use ic_btc_types::{GetUtxosRequest, GetUtxosResponse, UtxosFilter::MinConfirmations};
use ic_cdk::{call, export::Principal, trap};

/// Returns the actual UTXOs of the given Bitcoin `address` according to `min_confirmations`.
// TODO(ER-2579): Add pagination support to `get_utxos` (relying on EXC-1005).
pub(crate) async fn get_utxos(
    network: Network,
    address: &Address,
    min_confirmations: u32,
) -> Result<UtxosResult, MinConfirmationsTooHigh> {
    if min_confirmations > STABILITY_THRESHOLD {
        return Err(MinConfirmationsTooHigh);
    }
    let res: Result<(GetUtxosResponse,), _> = call(
        Principal::management_canister(),
        "bitcoin_get_utxos",
        (GetUtxosRequest {
            address: address.to_string(),
            network: from_bitcoin_network_to_ic_btc_types_network(network),
            filter: Some(MinConfirmations(min_confirmations)),
        },),
    )
    .await;

    match res {
        // Return the UTXOs to the caller.
        Ok(data) => Ok(UtxosResult {
            address: address.clone(),
            utxos: data.0.utxos,
        }),

        // The call to `get_utxos` was rejected for a given reason (e.g. not enough cycles were attached to the call).
        Err((rejection_code, message)) => trap(&format!(
            "Received a reject from Bitcoin canister.\nRejection Code: {:?}\nMessage: '{}'",
            rejection_code, message
        )),
    }
}

/// Returns the difference between the current UTXO state and the last seen state for this address.
/// The last seen state for an address is updated to the current unseen state by calling `update_state` or implicitly when invoking `get_utxos_update`.
/// If there are no changes to the UTXO set since the last call, the returned `UtxosUpdate` will be identical.
pub(crate) fn peek_utxos_update<C: BitcoinCanister>(
    bitcoin_agent: &BitcoinAgent<C>,
    address: &Address,
) -> Result<UtxosUpdate, AddressNotTracked> {
    if !bitcoin_agent.utxos_state_addresses.contains_key(address) {
        return Err(AddressNotTracked);
    }
    let utxos_state_address = bitcoin_agent.utxos_state_addresses.get(address).unwrap();
    Ok(UtxosUpdate::from_state(
        &utxos_state_address.seen_state,
        &utxos_state_address.unseen_state,
    ))
}

/// Updates the state of the `BitcoinAgent` for the given `address`.
/// This function doesn't invoke a Bitcoin integration API function.
pub(crate) fn update_state<C: BitcoinCanister>(
    bitcoin_agent: &mut BitcoinAgent<C>,
    address: &Address,
) -> Result<(), AddressNotTracked> {
    if !bitcoin_agent.utxos_state_addresses.contains_key(address) {
        return Err(AddressNotTracked);
    }
    let unseen_state = bitcoin_agent.utxos_state_addresses[address]
        .unseen_state
        .clone();
    bitcoin_agent
        .utxos_state_addresses
        .get_mut(address)
        .unwrap()
        .seen_state = unseen_state;
    Ok(())
}

/// Returns the difference in the set of UTXOs of an address controlled by the `BitcoinAgent` between the current state and the seen state when the function was last called, considering only UTXOs with the number of confirmations specified when adding the given address.
/// The returned `UtxosUpdate` contains the information which UTXOs were added and removed. If the function is called for the first time, the current set of UTXOs is returned.
/// Note that the function changes the state of the `BitcoinAgent`: A subsequent call will return changes to the UTXO set that have occurred since the last call.
pub(crate) fn get_utxos_update<C: BitcoinCanister>(
    bitcoin_agent: &mut BitcoinAgent<C>,
    address: &Address,
) -> Result<UtxosUpdate, AddressNotTracked> {
    let utxos_update = peek_utxos_update(bitcoin_agent, address)?;
    update_state(bitcoin_agent, address).unwrap();
    Ok(utxos_update)
}

/// Returns the balance of the given Bitcoin `address` according to `min_confirmations` from a given `bitcoin_agent`.
pub(crate) async fn get_balance<C: BitcoinCanister>(
    bitcoin_agent: &BitcoinAgent<C>,
    address: &Address,
    min_confirmations: u32,
) -> Result<Satoshi, MinConfirmationsTooHigh> {
    // Get the UTXOs for the given Bitcoin `address` according to `min_confirmations`.
    let res: Result<Vec<Utxo>, MinConfirmationsTooHigh> =
        bitcoin_agent.get_utxos(address, min_confirmations).await;

    match res {
        // Return the balance to the caller by summing the value of each UTXO.
        Ok(utxos) => Ok(get_balance_from_utxos(&utxos)),

        // The call to `get_utxos` returned an error.
        // Return this error to the caller.
        Err(error) => Err(error),
    }
}

/// Returns the total value of a UTXOs set.
pub(crate) fn get_balance_from_utxos(utxos: &[Utxo]) -> Satoshi {
    utxos.iter().map(|utxo| utxo.value).sum()
}

/// Returns the difference between the current balance state and the last seen state for this address.
/// The last seen state for an address is updated to the current unseen state by calling `update_state` or implicitly when invoking `get_balance_update`.
/// If there are no changes to the balance since the last call, the returned `BalanceUpdate` will be identical.
pub(crate) fn peek_balance_update<C: BitcoinCanister>(
    bitcoin_agent: &BitcoinAgent<C>,
    address: &Address,
) -> Result<BalanceUpdate, AddressNotTracked> {
    let utxos_update = peek_utxos_update(bitcoin_agent, address)?;
    Ok(BalanceUpdate::from(utxos_update))
}

/// Returns the difference in the balance of an address controlled by the `BitcoinAgent` between the current state and the seen state when the function was last called, considering only transactions with the specified number of confirmations.
/// The returned `BalanceUpdate` contains the information on how much balance was added and subtracted in total. If the function is called for the first time, the current balance of the address is returned.
/// It is equivalent to calling `get_utxos_update` and summing up the balances in the returned UTXOs.
pub(crate) fn get_balance_update<C: BitcoinCanister>(
    bitcoin_agent: &mut BitcoinAgent<C>,
    address: &Address,
) -> Result<BalanceUpdate, AddressNotTracked> {
    let utxos_update = get_utxos_update(bitcoin_agent, address)?;
    Ok(BalanceUpdate::from(utxos_update))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        agent,
        agent::tests::MOCK_AGENT,
        canister_mock::{
            get_init_balance_update, get_init_utxos, get_init_utxos_update, BitcoinCanisterMock,
        },
        AddressType, BalanceUpdate, OutPoint,
    };
    use bitcoin::Network;

    /// Check that `get_utxos` returns the correct address' UTXOs according to `min_confirmations`.
    #[tokio::test]
    async fn check_get_utxos() {
        let bitcoin_agent = agent::tests::new_mock(&Network::Regtest, &AddressType::P2pkh);
        let utxos = get_init_utxos();
        let canister_bitcoin_address = &bitcoin_agent.get_main_address();

        assert_eq!(
            bitcoin_agent.get_utxos(canister_bitcoin_address, 0).await,
            Ok(utxos.clone())
        );
        assert_eq!(
            bitcoin_agent.get_utxos(canister_bitcoin_address, 1).await,
            Ok(utxos)
        );
        assert_eq!(
            bitcoin_agent.get_utxos(canister_bitcoin_address, 2).await,
            Ok(vec![])
        );
    }

    /// Check that `peek_utxos_update` returns the correct `UtxosUpdate` associated to the Bitcoin agent's main address.
    #[tokio::test]
    async fn check_peek_utxos_update() {
        let mut bitcoin_agent = agent::tests::new_mock(&Network::Regtest, &AddressType::P2pkh);
        let utxos_update = get_init_utxos_update();
        let canister_bitcoin_address = &bitcoin_agent.get_main_address();
        apply_utxos_pattern(&mut bitcoin_agent, canister_bitcoin_address);

        for _ in 0..=1 {
            assert_eq!(
                bitcoin_agent.peek_utxos_update(canister_bitcoin_address),
                Ok(utxos_update.clone())
            );
        }
    }

    /// Check that `update_state` updates the Bitcoin agent's state according to its main address.
    #[tokio::test]
    async fn check_update_state() {
        let mut bitcoin_agent = agent::tests::new_mock(&Network::Regtest, &AddressType::P2pkh);
        let utxos_update = get_init_utxos_update();
        let canister_bitcoin_address = &bitcoin_agent.get_main_address();
        apply_utxos_pattern(&mut bitcoin_agent, canister_bitcoin_address);

        assert_eq!(
            bitcoin_agent.peek_utxos_update(canister_bitcoin_address),
            Ok(utxos_update),
            "Wrong value returned by peek_utxos_update (1)."
        );

        let added_utxo = Utxo {
            outpoint: OutPoint {
                txid: vec![0; 32],
                vout: 0,
            },
            value: 42_000,
            height: STABILITY_THRESHOLD + 1,
        };
        bitcoin_agent
            .bitcoin_canister
            .utxos
            .push(added_utxo.clone());
        bitcoin_agent.bitcoin_canister.tip_height += 1;

        assert_eq!(
            update_state(&mut bitcoin_agent, canister_bitcoin_address),
            Ok(()),
            "Wrong value returned by update_state."
        );

        apply_utxos_pattern(&mut bitcoin_agent, canister_bitcoin_address);

        let new_utxos_update = UtxosUpdate {
            added_utxos: vec![added_utxo],
            removed_utxos: vec![],
        };
        assert_eq!(
            bitcoin_agent.peek_utxos_update(canister_bitcoin_address),
            Ok(new_utxos_update),
            "Wrong value returned by peek_utxos_update (2)."
        );

        assert_eq!(bitcoin_agent.update_state(canister_bitcoin_address), Ok(()));

        assert_eq!(
            bitcoin_agent.peek_utxos_update(canister_bitcoin_address),
            Ok(UtxosUpdate {
                added_utxos: vec![],
                removed_utxos: vec![]
            })
        );
    }

    /// Check that `get_utxos_update` returns the correct `UtxosUpdate` associated to the Bitcoin agent main address.
    #[tokio::test]
    async fn check_get_utxos_update() {
        let mut bitcoin_agent = agent::tests::new_mock(&Network::Regtest, &AddressType::P2pkh);
        let utxos_update = get_init_utxos_update();
        let canister_bitcoin_address = &bitcoin_agent.get_main_address();
        apply_utxos_pattern(&mut bitcoin_agent, canister_bitcoin_address);

        assert_eq!(
            bitcoin_agent.get_utxos_update(canister_bitcoin_address),
            Ok(utxos_update)
        );

        assert_eq!(
            bitcoin_agent.get_utxos_update(canister_bitcoin_address),
            Ok(UtxosUpdate::new())
        );
    }

    /// Check that `get_balance` returns the correct address' balance according to `min_confirmations`.
    #[tokio::test]
    async fn check_get_balance() {
        let bitcoin_agent = agent::tests::new_mock(&Network::Regtest, &AddressType::P2pkh);
        let utxos = get_init_utxos();
        let balance = get_balance_from_utxos(&utxos);
        let canister_bitcoin_address = &bitcoin_agent.get_main_address();

        assert_eq!(
            bitcoin_agent.get_balance(canister_bitcoin_address, 0).await,
            Ok(balance)
        );
        assert_eq!(
            bitcoin_agent.get_balance(canister_bitcoin_address, 1).await,
            Ok(balance)
        );
        assert_eq!(
            bitcoin_agent.get_balance(canister_bitcoin_address, 2).await,
            Ok(0)
        );
    }

    /// Check that `peek_balance_update` returns the correct `BalanceUpdate` associated to the Bitcoin agent's main address.
    #[tokio::test]
    async fn check_peek_balance_update() {
        let mut bitcoin_agent = agent::tests::new_mock(&Network::Regtest, &AddressType::P2pkh);
        let balance_update = get_init_balance_update();
        let canister_bitcoin_address = &bitcoin_agent.get_main_address();
        apply_utxos_pattern(&mut bitcoin_agent, canister_bitcoin_address);

        for _ in 0..=1 {
            assert_eq!(
                bitcoin_agent.peek_balance_update(canister_bitcoin_address),
                Ok(balance_update.clone())
            );
        }
    }

    /// Check that `get_balance_update` returns the correct `BalanceUpdate` associated to the Bitcoin agent main address.
    #[tokio::test]
    async fn check_get_balance_update() {
        let mut bitcoin_agent = agent::tests::new_mock(&Network::Regtest, &AddressType::P2pkh);
        let balance_update = get_init_balance_update();
        let canister_bitcoin_address = &bitcoin_agent.get_main_address();
        apply_utxos_pattern(&mut bitcoin_agent, canister_bitcoin_address);

        assert_eq!(
            bitcoin_agent.get_balance_update(canister_bitcoin_address),
            Ok(balance_update)
        );

        assert_eq!(
            bitcoin_agent.get_balance_update(canister_bitcoin_address),
            Ok(BalanceUpdate::new())
        );
    }

    /// Apply update following the same pattern a canister developer will use.
    fn apply_utxos_pattern(
        bitcoin_agent: &mut BitcoinAgent<BitcoinCanisterMock>,
        address: &Address,
    ) {
        let utxos_args = bitcoin_agent.get_utxos_args(address, 0);
        let utxos_result = bitcoin_agent
            .get_utxos_from_args_test(utxos_args)
            .expect("Error while getting UTXOs result.");
        let _utxos_update = bitcoin_agent.apply_utxos(utxos_result);
    }

    /// We need to test library usage with thread_local agents as a canister developer would do.
    #[test]
    fn test_thread_local_peek_utxos_update() {
        // Build args.
        let address = MOCK_AGENT.with(|a| a.borrow().get_main_address());
        let args = MOCK_AGENT.with(|a| a.borrow().get_utxos_args(&address, STABILITY_THRESHOLD));
        let utxos = MOCK_AGENT.with(|a| a.borrow().get_utxos_from_args_test(args));
        let utxos = utxos.expect("Error while getting UTXOs result.");

        // Update agent state.
        let result = MOCK_AGENT.with(|a| a.borrow_mut().apply_utxos(utxos));
        assert!(!result.added_utxos.is_empty());
        let utxos_update_init = get_init_utxos_update();
        assert_eq!(utxos_update_init, result);

        // Call peek_utxos_update.
        let result = MOCK_AGENT.with(|a| a.borrow().peek_utxos_update(&address));
        let result = result.unwrap();
        let utxos_update = get_init_utxos_update();
        assert_eq!(utxos_update, result);
    }
}
