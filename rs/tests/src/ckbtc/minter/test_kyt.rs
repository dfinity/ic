use crate::ckbtc::lib::{
    activate_ecdsa_signature, create_canister, install_bitcoin_canister, install_kyt,
    install_ledger, install_minter, set_kyt_api_key, subnet_sys, upgrade_kyt,
    BTC_MIN_CONFIRMATIONS, KYT_FEE, TEST_KEY_LOCAL,
};
use crate::ckbtc::minter::utils::{
    assert_account_balance, assert_burn_transaction, assert_mint_transaction, assert_no_new_utxo,
    assert_no_transaction, ensure_wallet, generate_blocks, get_btc_address, get_btc_client,
    send_to_btc_address, start_canister, stop_canister, upgrade_canister, wait_for_bitcoin_balance,
    wait_for_ledger_balance, wait_for_mempool_change, BTC_BLOCK_REWARD,
};
use bitcoincore_rpc::RpcApi;
use candid::Nat;
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_kyt::KytMode;
use ic_ckbtc_minter::updates::get_withdrawal_account::compute_subaccount;
use ic_ckbtc_minter::updates::retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError};
use ic_ckbtc_minter::updates::update_balance::{UpdateBalanceArgs, UpdateBalanceError, UtxoStatus};
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on, runtime_from_url, UniversalCanister},
};
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
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
        let mut kyt_canister = create_canister(&runtime).await;

        let minting_user = minter_canister.canister_id().get();
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let agent_principal = agent.get_principal().unwrap();
        let kyt_id = install_kyt(
            &mut kyt_canister,
            &logger,
            Principal::from(minting_user),
            vec![agent_principal],
        )
        .await;
        set_kyt_api_key(&agent, &kyt_id.get().0, "fake key".to_string()).await;
        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&mut minter_canister, ledger_id, &logger, 0, kyt_id).await;
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
        upgrade_kyt(&mut kyt_canister, KytMode::RejectAll).await;

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

        stop_canister(&kyt_canister).await;
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
        start_canister(&kyt_canister).await;

        // Put the kyt canister into accept all utxos mode.
        upgrade_kyt(&mut kyt_canister, KytMode::AcceptAll).await;
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

        let _ = minter_agent.distribute_kyt_fee().await;

        wait_for_ledger_balance(
            &ledger_agent,
            &logger,
            Nat::from(2 * KYT_FEE),
            Account {
                owner: agent_principal,
                subaccount: None,
            },
        )
        .await;

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

        // Put the kyt canister into reject all utxos mode.
        upgrade_kyt(&mut kyt_canister, KytMode::RejectAll).await;

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
            assert_eq!(
                error_message,
                "Destination address is tainted, KYT check fee deducted: 0.00001001"
            );
        } else {
            panic!("Expected to see a tainted destination address.")
        }
        assert_burn_transaction(&ledger_agent, &logger, 4, &withdrawal_account, KYT_FEE).await;

        upgrade_kyt(&mut kyt_canister, KytMode::AcceptAll).await;
        let _ = minter_agent.distribute_kyt_fee().await;

        assert_mint_transaction(
            &ledger_agent,
            &logger,
            5,
            &Account {
                owner: agent_principal,
                subaccount: None,
            },
            KYT_FEE,
        )
        .await;

        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: retrieve_amount,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc")
            .expect("Error in retrieve_btc");
        assert_eq!(6, retrieve_result.block_index);
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
            retrieve_amount - minters_fee - KYT_FEE - bitcoin_network_fee,
            &btc_address2,
        )
        .await;

        // Amount expected to be left on withdrawal_account
        let expected_change_amount = transfer_amount - retrieve_amount - KYT_FEE;
        assert_account_balance(&ledger_agent, &withdrawal_account, expected_change_amount).await;

        let _ = minter_agent.distribute_kyt_fee().await;

        // In total we did 4 KYT checks: 2 address and 2 UTXOs
        let balance_kyt_provider = ledger_agent
            .balance_of(
                Account {
                    owner: agent_principal,
                    subaccount: None,
                },
                CallMode::Query,
            )
            .await
            .expect("Error while calling balance_of");
        assert_eq!(balance_kyt_provider, 4 * KYT_FEE);

        let metrics = minter_agent.get_metrics_map().await;
        let owed_kyt_amount = metrics.get("ckbtc_minter_owed_kyt_amount").unwrap().value;
        assert_eq!(owed_kyt_amount, 0_f64);
    });
}
