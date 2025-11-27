use anyhow::Result;
use candid::Principal;
use ic_agent::identity::Secp256k1Identity;
use ic_base_types::PrincipalId;
use ic_btc_checker::CheckMode as NewCheckMode;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::{
    lifecycle::upgrade::UpgradeArgs,
    state::Mode,
    updates::{
        get_withdrawal_account::compute_subaccount,
        update_balance::{UpdateBalanceArgs, UtxoStatus},
    },
};
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    systest,
    util::{UniversalCanister, assert_create_agent, block_on, runtime_from_url},
};
#[cfg(feature = "tla")]
use ic_tests_ckbtc::fetch_and_check_traces;
use ic_tests_ckbtc::{
    BTC_MIN_CONFIRMATIONS, CHECK_FEE, OVERALL_TIMEOUT, TIMEOUT_PER_TEST, ckbtc_setup,
    create_canister, install_bitcoin_canister, install_btc_checker, install_ledger, install_minter,
    subnet_app, subnet_sys, upgrade_btc_checker,
    utils::{
        BTC_BLOCK_REWARD, assert_mint_transaction, assert_no_new_utxo, assert_no_transaction,
        assert_temporarily_unavailable, generate_blocks, get_btc_address, get_rpc_client,
        start_canister, stop_canister, update_balance, upgrade_canister,
        upgrade_canister_with_args, wait_for_bitcoin_balance,
    },
};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use k256::elliptic_curve::SecretKey;
use rand::{SeedableRng, rngs::OsRng};
use rand_chacha::ChaChaRng;
use slog::{debug, info};

/// Test update_balance method of the minter canister.
/// Verify proper state preservation after canister update.
/// Verify proper utxo management in case of a ledger failure during the mint operation.
pub fn test_update_balance(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let subnet_app = subnet_app(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_node = subnet_app.nodes().next().expect("No node in app subnet.");

    // Get access to btc replica.
    let btc_rpc = get_rpc_client::<bitcoin::Network>(&env);

    let default_btc_address = btc_rpc.get_address().unwrap();
    // Creating the 10 first block to reach the min confirmations of the minter canister.
    debug!(
        &logger,
        "Generating 10 blocks to default address: {}", default_btc_address
    );
    btc_rpc
        .generate_to_address(10, default_btc_address)
        .unwrap();

    block_on(async {
        let sys_runtime =
            runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
        let runtime = runtime_from_url(app_node.get_public_url(), app_node.effective_canister_id());
        install_bitcoin_canister(&sys_runtime, &logger).await;

        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let mut btc_checker_canister = create_canister(&runtime).await;

        let minting_user = minter_canister.canister_id().get();
        let agent = assert_create_agent(app_node.get_public_url().as_str()).await;
        let btc_checker_id = install_btc_checker(&mut btc_checker_canister, &env).await;
        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id =
            install_minter(&mut minter_canister, ledger_id, &logger, 0, btc_checker_id).await;
        let minter = Principal::from(minter_id.get());

        let ledger = Principal::from(ledger_id.get());
        let universal_canister =
            UniversalCanister::new_with_retries(&agent, app_node.effective_canister_id(), &logger)
                .await;
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
        debug!(&logger, "New identity principal: {}", caller);
        let subaccount0 = compute_subaccount(PrincipalId::from(caller), 0);
        let subaccount1 = compute_subaccount(PrincipalId::from(caller), 567);
        let subaccount2 = compute_subaccount(PrincipalId::from(caller), 890);
        let subaccount3 = compute_subaccount(PrincipalId::from(caller), 42);
        let subaccount4 = compute_subaccount(PrincipalId::from(caller), 84);

        let account1 = Account {
            owner: caller,
            subaccount: Some(subaccount1),
        };
        let account2 = Account {
            owner: caller,
            subaccount: Some(subaccount2),
        };
        let account3 = Account {
            owner: caller,
            subaccount: Some(subaccount3),
        };

        // Because bitcoind only allows to see one's own transaction, and we
        // are using multiple addresses in this test. We have to change check
        // mode to AcceptAll, otherwise bitcoind will return 500 error.
        upgrade_btc_checker(&mut btc_checker_canister, NewCheckMode::AcceptAll).await;

        // Get the BTC address of the caller's sub-accounts.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;
        let btc_address1 = get_btc_address(&minter_agent, &logger, subaccount1).await;
        let btc_address2 = get_btc_address(&minter_agent, &logger, subaccount2).await;
        let btc_address3 = get_btc_address(&minter_agent, &logger, subaccount3).await;
        let btc_address4 = get_btc_address(&minter_agent, &logger, subaccount4).await;

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
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_REWARD,
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
        assert!(!update_result.is_empty());
        // The other subaccount should not be impacted.
        assert_no_new_utxo(&minter_agent, &subaccount2).await;
        for update_balance_entry in &update_result {
            if let UtxoStatus::Minted { block_index, .. } = &update_balance_entry {
                assert_mint_transaction(
                    &ledger_agent,
                    &logger,
                    *block_index,
                    &account1,
                    BTC_BLOCK_REWARD - CHECK_FEE,
                )
                .await;
            } else {
                panic!("expected to have one minted utxo, got: {update_result:?}");
            }
        }

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
            2 * BTC_MIN_CONFIRMATIONS * BTC_BLOCK_REWARD,
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
        assert!(!update_result.is_empty());
        // The other subaccount should not be impacted.
        assert_no_new_utxo(&minter_agent, &subaccount1).await;

        for update_balance_entry in &update_result {
            if let UtxoStatus::Minted { block_index, .. } = &update_balance_entry {
                assert_mint_transaction(
                    &ledger_agent,
                    &logger,
                    *block_index,
                    &account2,
                    BTC_BLOCK_REWARD - CHECK_FEE,
                )
                .await;
            } else {
                panic!("expected to have one minted utxo, got {update_result:?}");
            }
        }

        // Calling update_balance again will always trigger a NoNewUtxo error.
        upgrade_canister(&mut minter_canister).await;
        assert_no_new_utxo(&minter_agent, &subaccount2).await;

        // Check that we can update balance in the restricted mode.
        let caller = agent.get_principal().unwrap();
        upgrade_canister_with_args(
            &mut minter_canister,
            &UpgradeArgs {
                mode: Some(Mode::RestrictedTo(vec![caller])),
                ..UpgradeArgs::default()
            },
        )
        .await;
        assert_no_new_utxo(&minter_agent, &subaccount2).await;
        upgrade_canister_with_args(
            &mut minter_canister,
            &UpgradeArgs {
                mode: Some(Mode::GeneralAvailability),
                ..UpgradeArgs::default()
            },
        )
        .await;
        generate_blocks(&btc_rpc, &logger, 1, &btc_address3);
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address4);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_REWARD,
            &btc_address4,
        )
        .await;

        // We create a new agent with a different identity
        // to have caller != new_caller
        let mut mutable_agent = assert_create_agent(app_node.get_public_url().as_str()).await;
        let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
        let identity = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
        mutable_agent.set_identity(identity);
        let minter_agent = CkBtcMinterAgent {
            agent: mutable_agent.clone(),
            minter_canister_id: minter,
        };

        let new_caller = mutable_agent
            .get_principal()
            .expect("Error while getting principal.");
        assert!(caller != new_caller);
        debug!(&logger, "New identity principal: {}", caller);

        // owner stays the same as previously
        // only the caller changes.
        let update_result = minter_agent
            .update_balance(UpdateBalanceArgs {
                owner: Some(caller),
                subaccount: Some(subaccount3),
            })
            .await
            .expect("Error while calling update_balance")
            .unwrap();
        assert!(!update_result.is_empty());
        for update_balance_entry in &update_result {
            if let UtxoStatus::Minted { block_index, .. } = &update_balance_entry {
                assert_mint_transaction(
                    &ledger_agent,
                    &logger,
                    *block_index,
                    &account3,
                    BTC_BLOCK_REWARD - CHECK_FEE,
                )
                .await;
            } else {
                panic!("expected to have one minted utxo, got: {update_result:?}");
            }
        }

        #[cfg(feature = "tla")]
        fetch_and_check_traces(minter_canister.clone(), runtime.as_ref());
    });
}
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(TIMEOUT_PER_TEST)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(ckbtc_setup)
        .add_test(systest!(test_update_balance))
        .execute_from_args()?;
    Ok(())
}
