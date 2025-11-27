use anyhow::Result;
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_btc_checker::CheckMode as NewCheckMode;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::{
    lifecycle::upgrade::UpgradeArgs,
    state::{Mode, RetrieveBtcRequest, eventlog::EventType},
    updates::{
        get_withdrawal_account::compute_subaccount,
        retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError},
        update_balance::UtxoStatus,
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
use ic_tests_ckbtc::{
    BTC_MIN_CONFIRMATIONS, CHECK_FEE, OVERALL_TIMEOUT, RETRIEVE_BTC_MIN_AMOUNT, TIMEOUT_PER_TEST,
    TRANSFER_FEE, ckbtc_setup, create_canister, install_bitcoin_canister, install_btc_checker,
    install_ledger, install_minter, subnet_app, subnet_sys, upgrade_btc_checker,
    utils::{
        BTC_BLOCK_REWARD, assert_account_balance, assert_burn_transaction, assert_mint_transaction,
        generate_blocks, get_btc_address, get_rpc_client, update_balance,
        upgrade_canister_with_args, wait_for_bitcoin_balance,
    },
};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::{account::Account, transfer::TransferArg};
use slog::{debug, info};

#[cfg(feature = "tla")]
use ic_tests_ckbtc::fetch_and_check_traces;

/// Test retrieve_btc method of the minter canister.
pub fn test_retrieve_btc(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let subnet_app = subnet_app(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_node = subnet_app.nodes().next().expect("No node in app subnet.");
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
        let subaccount0 = compute_subaccount(PrincipalId::from(caller), 0);
        let subaccount1 = compute_subaccount(PrincipalId::from(caller), 567);
        let subaccount2 = compute_subaccount(PrincipalId::from(caller), 890);
        let account1 = Account {
            owner: caller,
            subaccount: Some(subaccount1),
        };

        // Because bitcoind only allows to see one's own transaction, and we
        // are using multiple addresses in this test. We have to change check
        // mode to AcceptAll, otherwise bitcoind will return 500 error.
        upgrade_btc_checker(&mut btc_checker_canister, NewCheckMode::AcceptAll).await;

        // Get the BTC address of the caller's sub-accounts.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;
        let btc_address1 = get_btc_address(&minter_agent, &logger, subaccount1).await;
        let btc_address2 = get_btc_address(&minter_agent, &logger, subaccount2).await;

        // -- beginning of test logic --
        // Scenario: We are minting btc to account 1, minting ckbtc out of it,
        // transferring ckbtc to the withdraw account, calling retrieve_btc.

        // Start by creating ckBTC to the first subaccount.
        generate_blocks(&btc_rpc, &logger, 3, &btc_address1);
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_REWARD,
            &btc_address0,
        )
        .await;
        let update_result = update_balance(&minter_agent, &logger, Some(subaccount1))
            .await
            .unwrap();
        assert!(!update_result.is_empty());
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

        // Now test retrieve_btc logic.
        // Get the subaccount used for btc retrieval.
        let withdrawal_account = minter_agent
            .get_withdrawal_account()
            .await
            .expect("Error while calling get_withdrawal_account");
        info!(&logger, "Transferring to the minter the ckBTC to be burned");
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
        info!(
            &logger,
            "Verify account1 balance on the ledger (adjusted for fee)"
        );
        assert_account_balance(
            &ledger_agent,
            &account1,
            3 * (BTC_BLOCK_REWARD - CHECK_FEE) - transfer_amount - TRANSFER_FEE,
        )
        .await;
        info!(&logger, "Verify withdrawal_account balance on the ledger");
        assert_account_balance(&ledger_agent, &withdrawal_account, transfer_amount).await;

        info!(&logger, "Call retrieve_btc");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 35_000_000,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc")
            .expect("Error in retrieve_btc");
        assert_eq!(4, retrieve_result.block_index);

        let events: Vec<_> = minter_agent
            .get_events(0, 1000)
            .await
            .expect("failed to fetch minter's event log")
            .iter()
            .map(|event| event.payload.clone())
            .collect();
        assert!(
            events.iter().any(|e| matches!(
                e,
                EventType::AcceptedRetrieveBtcRequest(RetrieveBtcRequest { block_index: 4, .. })
            )),
            "missing accepted_retrieve_btc_request event in the log: {events:?}"
        );

        info!(&logger, "Call retrieve_btc with insufficient funds");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 35_000_000,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc");
        assert_eq!(
            Err(RetrieveBtcError::InsufficientFunds {
                balance: 7_000_000u64
            }),
            retrieve_result
        );

        info!(&logger, "Call retrieve_btc with insufficient amount");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 33,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc");
        assert_eq!(
            Err(RetrieveBtcError::AmountTooLow(RETRIEVE_BTC_MIN_AMOUNT)),
            retrieve_result
        );

        // Verify that a burn transaction occurred.
        assert_burn_transaction(&ledger_agent, &logger, 4, &withdrawal_account, 35_000_000).await;

        // Check that we can retrieve btc in the restricted mode.
        let caller = agent.get_principal().unwrap();
        upgrade_canister_with_args(
            &mut minter_canister,
            &UpgradeArgs {
                mode: Some(Mode::RestrictedTo(vec![caller])),
                ..UpgradeArgs::default()
            },
        )
        .await;
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 1_000_000,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc")
            .expect("failed to retrieve btc");
        assert_eq!(5, retrieve_result.block_index);

        #[cfg(feature = "tla")]
        fetch_and_check_traces(minter_canister.clone(), runtime.as_ref());
    });
}
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(TIMEOUT_PER_TEST)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(ckbtc_setup)
        .add_test(systest!(test_retrieve_btc))
        .execute_from_args()?;
    Ok(())
}
