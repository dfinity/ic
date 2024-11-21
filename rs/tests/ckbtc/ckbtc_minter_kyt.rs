use anyhow::Result;

use bitcoincore_rpc::RpcApi;
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_btc_kyt::KytMode as NewKytMode;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::updates::{
    get_withdrawal_account::compute_subaccount,
    retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError},
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UtxoStatus},
};
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    systest,
    util::{assert_create_agent, block_on, runtime_from_url, UniversalCanister},
};
use ic_tests_ckbtc::{
    activate_ecdsa_signature, create_canister, install_bitcoin_canister, install_ledger,
    install_minter, install_new_kyt, setup, subnet_sys, upgrade_new_kyt,
    utils::{
        assert_account_balance, assert_mint_transaction, assert_no_new_utxo, assert_no_transaction,
        ensure_wallet, generate_blocks, get_btc_address, get_btc_client, send_to_btc_address,
        start_canister, stop_canister, upgrade_canister, wait_for_bitcoin_balance,
        wait_for_mempool_change, BTC_BLOCK_REWARD,
    },
    BTC_MIN_CONFIRMATIONS, KYT_FEE, TEST_KEY_LOCAL,
};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use slog::debug;

/// Test update_balance method of the minter canister.
/// Verify proper state preservation after canister update.
/// Verify proper utxo management in case of a ledger failure during the mint operation.
pub fn test_kyt(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    // Get access to btc replica.
    let btc_rpc = get_btc_client(&env);

    // Create wallet if required.
    ensure_wallet(&btc_rpc, &logger);

    let default_btc_address = btc_rpc.get_new_address(None, None).unwrap();
    // Creating the 101 first block to reach the min confirmations to spend a coinbase utxo.
    debug!(
        &logger,
        "Generating 101 blocks to default address: {}", &default_btc_address
    );
    btc_rpc
        .generate_to_address(101, &default_btc_address)
        .unwrap();

    block_on(async {
        let runtime = runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
        install_bitcoin_canister(&runtime, &logger).await;

        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let mut new_kyt_canister = create_canister(&runtime).await;

        let minting_user = minter_canister.canister_id().get();
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let new_kyt_id = install_new_kyt(&mut new_kyt_canister, &env).await;
        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id =
            install_minter(&mut minter_canister, ledger_id, &logger, 0, new_kyt_id).await;
        let minter = Principal::from(minter_id.get());

        let ledger = Principal::from(ledger_id.get());
        let universal_canister =
            UniversalCanister::new_with_retries(&agent, sys_node.effective_canister_id(), &logger)
                .await;
        activate_ecdsa_signature(sys_node, subnet_sys.subnet_id, TEST_KEY_LOCAL, &logger).await;

        let ledger_agent = Icrc1Agent {
            agent: agent.clone(),
            ledger_canister_id: ledger,
        };
        let minter_agent = CkBtcMinterAgent {
            agent: agent.clone(),
            minter_canister_id: minter,
        };

        let caller = agent
            .get_principal()
            .expect("Error while getting principal.");
        let subaccount0 = compute_subaccount(PrincipalId::from(caller), 0);
        let subaccount1 = compute_subaccount(PrincipalId::from(caller), 567);
        let subaccount2 = compute_subaccount(PrincipalId::from(caller), 666);
        let account1 = Account {
            owner: caller,
            subaccount: Some(subaccount1),
        };

        // Get the BTC address of the caller's sub-accounts.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;
        let btc_address1 = get_btc_address(&minter_agent, &logger, subaccount1).await;
        let btc_address2 = get_btc_address(&minter_agent, &logger, subaccount2).await;

        // -- beginning of test logic --

        // We shouldn't have any new utxo for now.
        assert_no_new_utxo(&minter_agent, &subaccount0).await;
        assert_no_new_utxo(&minter_agent, &subaccount1).await;

        // Mint block to the first sub-account (with single utxo).
        let first_transfer_amount = 100_000_000;
        const BITCOIN_NETWORK_TRANSFER_FEE: u64 = 2820;
        send_to_btc_address(&btc_rpc, &logger, &btc_address1, first_transfer_amount).await;
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);

        // Put the kyt canister into reject all utxos mode.
        upgrade_new_kyt(&mut new_kyt_canister, NewKytMode::RejectAll).await;

        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_REWARD + BITCOIN_NETWORK_TRANSFER_FEE,
            &btc_address0,
        )
        .await;
        let update_balance_tainted_result = minter_agent
            .update_balance(UpdateBalanceArgs {
                owner: None,
                subaccount: Some(subaccount1),
            })
            .await
            .expect("Error while calling update_balance")
            .expect("expected to have at a valid result");
        assert_eq!(update_balance_tainted_result.len(), 1);

        if let UtxoStatus::Tainted(_) = &update_balance_tainted_result[0] {
        } else {
            panic!("expected the minter to see one tainted utxo");
        }
        assert_no_transaction(&ledger_agent, &logger).await;

        upgrade_canister(&mut minter_canister).await;
        // If the kyt canister is unavailable we should get an error.
        send_to_btc_address(&btc_rpc, &logger, &btc_address1, first_transfer_amount).await;
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            2 * BTC_MIN_CONFIRMATIONS * BTC_BLOCK_REWARD + 2 * BITCOIN_NETWORK_TRANSFER_FEE,
            &btc_address0,
        )
        .await;

        stop_canister(&new_kyt_canister).await;
        let update_balance_kyt_unavailable = minter_agent
            .update_balance(UpdateBalanceArgs {
                owner: None,
                subaccount: Some(subaccount1),
            })
            .await
            .expect("Error while calling update_balance");
        match update_balance_kyt_unavailable {
            Err(UpdateBalanceError::TemporarilyUnavailable(_)) => (),
            other => {
                panic!(
                    "Expected the KYT canister to be unavailable, got {:?}",
                    other
                );
            }
        }
        start_canister(&new_kyt_canister).await;

        upgrade_new_kyt(&mut new_kyt_canister, NewKytMode::Normal).await;
        // Now that the kyt canister is available and accept all utxos
        // we should be able to mint new utxos.
        let update_balance_new_utxos = minter_agent
            .update_balance(UpdateBalanceArgs {
                owner: None,
                subaccount: Some(subaccount1),
            })
            .await
            .expect("Error while calling update_balance")
            .expect("Expected to have at least one utxo result.");
        assert_eq!(update_balance_new_utxos.len(), 1);

        if let UtxoStatus::Minted { block_index, .. } = &update_balance_new_utxos[0] {
            assert_mint_transaction(
                &ledger_agent,
                &logger,
                *block_index,
                &account1,
                first_transfer_amount - KYT_FEE - BITCOIN_NETWORK_TRANSFER_FEE,
            )
            .await;
        } else {
            panic!("expected the minter to see one not tainted utxo");
        }

        stop_canister(&ledger_canister).await;
        send_to_btc_address(&btc_rpc, &logger, &btc_address1, first_transfer_amount).await;
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            3 * BTC_MIN_CONFIRMATIONS * BTC_BLOCK_REWARD + 3 * BITCOIN_NETWORK_TRANSFER_FEE,
            &btc_address0,
        )
        .await;

        let update_balance_new_utxos = minter_agent
            .update_balance(UpdateBalanceArgs {
                owner: None,
                subaccount: Some(subaccount1),
            })
            .await
            .expect("Error while calling update_balance")
            .expect("Expected to have at least one utxo result.");
        assert_eq!(update_balance_new_utxos.len(), 1);

        if let UtxoStatus::Checked(_) = &update_balance_new_utxos[0] {
        } else {
            panic!("Expected to have checked the utxos but not minted");
        }

        start_canister(&ledger_canister).await;
        let update_balance_new_utxos = minter_agent
            .update_balance(UpdateBalanceArgs {
                owner: None,
                subaccount: Some(subaccount1),
            })
            .await
            .expect("Error while calling update_balance")
            .expect("Expected to have at least one utxo result.");
        assert_eq!(update_balance_new_utxos.len(), 1);
        if let UtxoStatus::Minted { block_index, .. } = &update_balance_new_utxos[0] {
            assert_mint_transaction(
                &ledger_agent,
                &logger,
                *block_index,
                &account1,
                first_transfer_amount - KYT_FEE - BITCOIN_NETWORK_TRANSFER_FEE,
            )
            .await;
        } else {
            panic!("expected the minter to see one clean utxo");
        }

        let metrics = minter_agent.get_metrics_map().await;
        let owed_kyt_amount_after_update_balance =
            metrics.get("ckbtc_minter_owed_kyt_amount").unwrap().value;
        assert_eq!(owed_kyt_amount_after_update_balance as u64, 0);

        // Now let's send ckBTC back to the BTC network
        let withdrawal_account = minter_agent
            .get_withdrawal_account()
            .await
            .expect("Error while calling get_withdrawal_account");
        let transfer_amount = 42_000_000;

        let transfer_result = ledger_agent
            .transfer(TransferArg {
                from_subaccount: Some(subaccount1),
                to: withdrawal_account,
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(transfer_amount),
            })
            .await
            .expect("Error while calling transfer")
            .expect("Error during transfer");
        debug!(
            &logger,
            "Transfer to the minter account occurred at block {}", transfer_result
        );
        let retrieve_amount: u64 = 35_000_000;

        // Put the new kyt canister into reject all utxos mode.
        upgrade_new_kyt(&mut new_kyt_canister, NewKytMode::RejectAll).await;

        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: retrieve_amount,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc");

        if let Err(RetrieveBtcError::GenericError {
            error_message,
            error_code,
        }) = retrieve_result
        {
            assert_eq!(error_code, 1);
            assert_eq!(error_message, "Destination address is tainted");
            // assert that the ckBTC ledger didn't add more transactions
            let txs = ledger_agent
                .get_blocks(GetBlocksRequest {
                    start: transfer_result,
                    length: 10_u8.into(),
                })
                .await
                .expect("Error while calling ledger get_blocks");
            assert_eq!(txs.blocks.len(), 1);
        } else {
            panic!("Expected to see a tainted destination address.")
        }

        upgrade_new_kyt(&mut new_kyt_canister, NewKytMode::Normal).await;

        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: retrieve_amount,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc")
            .expect("Error in retrieve_btc");
        assert_eq!(3, retrieve_result.block_index);
        let _mempool_txids = wait_for_mempool_change(&btc_rpc, &logger).await;
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        // We can compute the minter's fee
        let minters_fee: u64 = ic_ckbtc_minter::MINTER_FEE_PER_INPUT
            + ic_ckbtc_minter::MINTER_FEE_PER_OUTPUT * 2
            + ic_ckbtc_minter::MINTER_FEE_CONSTANT;
        // Use the following estimator : https://btc.network/estimate
        // 1 input and 2 outputs => 141 vbyte
        // The regtest network fee defined in ckbtc/minter/src/lib.rs is 5 sat/vbyte.
        let bitcoin_network_fee = 141 * 5;

        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            retrieve_amount - minters_fee - bitcoin_network_fee,
            &btc_address2,
        )
        .await;

        // Amount expected to be left on withdrawal_account
        let expected_change_amount = transfer_amount - retrieve_amount;
        assert_account_balance(&ledger_agent, &withdrawal_account, expected_change_amount).await;

        let metrics = minter_agent.get_metrics_map().await;
        let owed_kyt_amount = metrics.get("ckbtc_minter_owed_kyt_amount").unwrap().value;
        assert_eq!(owed_kyt_amount, 0_f64);
    });
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_kyt))
        .execute_from_args()?;
    Ok(())
}
