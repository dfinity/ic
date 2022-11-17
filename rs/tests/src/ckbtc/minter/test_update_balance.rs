use crate::ckbtc::minter::utils::{
    assert_mint_transaction, assert_no_new_utxo, assert_no_transaction,
    assert_temporarily_unavailable, ensure_wallet, generate_blocks, get_btc_address,
    get_btc_client, start_canister, stop_canister, update_balance, upgrade_canister,
    wait_for_bitcoin_balance, BTC_BLOCK_SIZE, BTC_MIN_CONFIRMATIONS,
};
use crate::{
    ckbtc::lib::{
        activate_ecdsa_signature, create_canister, install_ledger, install_minter, subnet_app,
        subnet_sys, TEST_KEY_LOCAL,
    },
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on, runtime_from_url, UniversalCanister},
};
use bitcoincore_rpc::RpcApi;
use candid::Principal;
use ic_base_types::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::updates::get_withdrawal_account::compute_subaccount;
use ic_icrc1::Account;
use ic_icrc1_agent::Icrc1Agent;
use slog::{debug, info};

/// Test update_balance method of the minter canister.
/// Verify proper state preservation after canister update.
/// Verify proper utxo management in case of a ledger failure during the mint operation.
pub fn test_update_balance(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;

    // Get access to btc replica.
    let btc_rpc = get_btc_client(&env);

    // Create wallet if required.
    ensure_wallet(&btc_rpc, &logger);

    let default_btc_address = btc_rpc.get_new_address(None, None).unwrap();
    // Creating the 10 first block to reach the min confirmations of the minter canister.
    debug!(
        &logger,
        "Generating 10 blocks to default address: {}", &default_btc_address
    );
    btc_rpc
        .generate_to_address(10, &default_btc_address)
        .unwrap();

    block_on(async {
        let runtime = runtime_from_url(node.get_public_url());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let minting_user = minter_canister.canister_id().get();
        let ledger_id = install_ledger(&env, &mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&env, &mut minter_canister, ledger_id, &logger).await;
        let minter = Principal::from(minter_id.get());
        let ledger = Principal::from(ledger_id.get());
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        let universal_canister = UniversalCanister::new(&agent, node.effective_canister_id()).await;
        activate_ecdsa_signature(sys_node, app_subnet_id, TEST_KEY_LOCAL, &logger).await;

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
        let subaccount2 = compute_subaccount(PrincipalId::from(caller), 890);
        let account1 = Account {
            owner: PrincipalId::from(caller),
            subaccount: Some(subaccount1),
        };
        let account2 = Account {
            owner: PrincipalId::from(caller),
            subaccount: Some(subaccount2),
        };

        // Get the BTC address of the caller's sub-accounts.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;
        let btc_address1 = get_btc_address(&minter_agent, &logger, subaccount1).await;
        let btc_address2 = get_btc_address(&minter_agent, &logger, subaccount2).await;

        // -- beginning of test logic --

        // We shouldn't have any new utxo for now.
        assert_no_new_utxo(&minter_agent, &subaccount0).await;
        assert_no_new_utxo(&minter_agent, &subaccount1).await;
        assert_no_new_utxo(&minter_agent, &subaccount2).await;

        // Mint block to the first sub-account (with single utxo).
        generate_blocks(&btc_rpc, &logger, 3, &btc_address1);
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_SIZE,
            &btc_address0,
        )
        .await;

        // Without calling update_balance, ledger balance shouldn't change even with new utxo.
        // Verify that no transaction appears on the ledger.
        assert_no_transaction(&ledger_agent, &logger).await;

        // Verify that calling update_balance on one account doesn't impact the others.
        debug!(&logger, "Calling update balance on first subaccount.");
        let update_result = update_balance(&minter_agent, &logger, Some(subaccount1))
            .await
            .unwrap();
        // The other subaccount should not be impacted.
        assert_no_new_utxo(&minter_agent, &subaccount2).await;
        assert_mint_transaction(
            &ledger_agent,
            &logger,
            update_result.block_index,
            &account1,
            3 * BTC_BLOCK_SIZE,
        )
        .await;
        // Calling update_balance again will always trigger a NoNewUtxo error.
        upgrade_canister(&mut minter_canister).await;
        assert_no_new_utxo(&minter_agent, &subaccount1).await;

        // Now triggering a failure on the ledger canister.
        info!(&logger, "Simulating failure on the ledger canister");
        stop_canister(&ledger_canister).await;

        // Mint blocks to the second sub-account (with multiple utxos).
        generate_blocks(&btc_rpc, &logger, 5, &btc_address2);
        generate_blocks(&btc_rpc, &logger, 1, &btc_address2);
        generate_blocks(&btc_rpc, &logger, 1, &btc_address2);
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            2 * BTC_MIN_CONFIRMATIONS * BTC_BLOCK_SIZE,
            &btc_address0,
        )
        .await;

        debug!(
            &logger,
            "Calling update balance on second subaccount with missing ledger."
        );
        assert_temporarily_unavailable(&minter_agent, &subaccount2).await;

        // The ledger canister is back online.
        start_canister(&ledger_canister).await;

        debug!(
            &logger,
            "Calling update balance on second subaccount with ledger started again."
        );
        let update_result = update_balance(&minter_agent, &logger, Some(subaccount2))
            .await
            .unwrap();
        // The other subaccount should not be impacted.
        assert_no_new_utxo(&minter_agent, &subaccount1).await;
        assert_mint_transaction(
            &ledger_agent,
            &logger,
            update_result.block_index,
            &account2,
            7 * BTC_BLOCK_SIZE,
        )
        .await;
        // Calling update_balance again will always trigger a NoNewUtxo error.
        upgrade_canister(&mut minter_canister).await;
        assert_no_new_utxo(&minter_agent, &subaccount2).await;
    });
}
