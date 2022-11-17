use crate::ckbtc::minter::utils::{
    assert_account_balance, assert_burn_transaction, assert_mint_transaction, ensure_wallet,
    generate_blocks, get_btc_address, get_btc_client, update_balance, wait_for_bitcoin_balance,
    BTC_BLOCK_SIZE, BTC_MIN_CONFIRMATIONS,
};
use crate::{
    ckbtc::lib::{
        activate_ecdsa_signature, create_canister, install_ledger, install_minter, subnet_app,
        subnet_sys, RETRIEVE_BTC_MIN_AMOUNT, TEST_KEY_LOCAL, TRANSFER_FEE,
    },
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on, runtime_from_url, UniversalCanister},
};
use bitcoincore_rpc::RpcApi;
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::updates::{
    get_withdrawal_account::compute_subaccount,
    retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError},
};
use ic_icrc1::endpoints::TransferArg;
use ic_icrc1::Account;
use ic_icrc1_agent::Icrc1Agent;
use slog::{debug, info};

/// Test retrieve_btc method of the minter canister.
pub fn test_retrieve_btc(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;
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
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_SIZE,
            &btc_address0,
        )
        .await;
        let update_result = update_balance(&minter_agent, &logger, Some(subaccount1))
            .await
            .unwrap();
        assert_mint_transaction(
            &ledger_agent,
            &logger,
            update_result.block_index,
            &account1,
            3 * BTC_BLOCK_SIZE,
        )
        .await;

        // Now test retrieve_btc logic.
        // Get the subaccount used for btc retrieval.
        let withdrawal_account = minter_agent
            .get_withdrawal_account()
            .await
            .expect("Error while calling get_withdrawal_account")
            .account;
        info!(&logger, "Transferring to the minter the ckBTC to be burned");
        let transfer_amount = 42_000_000;
        let transfer_result = ledger_agent
            .transfer(TransferArg {
                from_subaccount: Some(subaccount1),
                to: withdrawal_account.clone(),
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
            3 * BTC_BLOCK_SIZE - transfer_amount - TRANSFER_FEE,
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
        assert_eq!(2, retrieve_result.block_index);

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
        assert_burn_transaction(&ledger_agent, &logger, 2, &withdrawal_account, 35_000_000).await;
    });
}
