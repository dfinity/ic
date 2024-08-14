use crate::ckbtc::lib::{
    activate_ecdsa_signature, create_canister, install_bitcoin_canister, install_kyt,
    install_ledger, install_minter, set_kyt_api_key, subnet_sys, BTC_MIN_CONFIRMATIONS, KYT_FEE,
    RETRIEVE_BTC_MIN_AMOUNT, TEST_KEY_LOCAL, TRANSFER_FEE,
};
use crate::ckbtc::minter::utils::{
    assert_account_balance, assert_burn_transaction, assert_mint_transaction, ensure_wallet,
    generate_blocks, get_btc_address, get_btc_client, update_balance, upgrade_canister_with_args,
    wait_for_bitcoin_balance, BTC_BLOCK_REWARD,
};
use bitcoincore_rpc::RpcApi;
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter::state::{eventlog::Event, Mode, RetrieveBtcRequest};
use ic_ckbtc_minter::updates::update_balance::UtxoStatus;
use ic_ckbtc_minter::updates::{
    get_withdrawal_account::compute_subaccount,
    retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError},
};
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on, runtime_from_url, UniversalCanister},
};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use slog::{debug, info};

/// Test retrieve_btc method of the minter canister.
pub fn test_retrieve_btc(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let btc_rpc = get_btc_client(&env);
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
        let subaccount2 = compute_subaccount(PrincipalId::from(caller), 890);
        let account1 = Account {
            owner: caller,
            subaccount: Some(subaccount1),
        };

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
                    BTC_BLOCK_REWARD - KYT_FEE,
                )
                .await;
            } else {
                panic!("expected to have one minted utxo, got: {:?}", update_result);
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
            3 * (BTC_BLOCK_REWARD - KYT_FEE) - transfer_amount - TRANSFER_FEE,
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

        let events = minter_agent
            .get_events(0, 1000)
            .await
            .expect("failed to fetch minter's event log");
        assert!(
            events.iter().any(|e| matches!(
                e,
                Event::AcceptedRetrieveBtcRequest(RetrieveBtcRequest { block_index: 4, .. })
            )),
            "missing accepted_retrieve_btc_request event in the log: {:?}",
            events
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
    });
}
