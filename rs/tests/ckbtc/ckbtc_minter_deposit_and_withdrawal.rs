use anyhow::Result;
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_btc_adapter_test_utils::bitcoin::{Txid, hashes::Hash};
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::{
    state::{RetrieveBtcRequest, RetrieveBtcStatus, eventlog::EventType},
    updates::{get_withdrawal_account::compute_subaccount, retrieve_btc::RetrieveBtcArgs},
};
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    systest,
    util::{assert_create_agent, block_on, runtime_from_url},
};
#[cfg(feature = "tla")]
use ic_tests_ckbtc::fetch_and_check_traces;
use ic_tests_ckbtc::{
    BTC_MIN_CONFIRMATIONS, CHECK_FEE, OVERALL_TIMEOUT, TIMEOUT_PER_TEST, TRANSFER_FEE, ckbtc_setup,
    create_canister, install_bitcoin_canister, install_btc_checker, install_ledger, install_minter,
    subnet_app, subnet_sys,
    utils::{
        BITCOIN_NETWORK_TRANSFER_FEE, generate_blocks, get_btc_address, get_rpc_client,
        send_to_btc_address, wait_for_finalization, wait_for_mempool_change, wait_for_signed_tx,
        wait_for_update_balance,
    },
};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use slog::{debug, info};

pub fn test_deposit_and_withdrawal(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let subnet_app = subnet_app(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_node = subnet_app.nodes().next().expect("No node in app subnet.");
    let btc_rpc = get_rpc_client::<bitcoin::Network>(&env);

    let default_btc_address = btc_rpc.get_address().unwrap();
    // Creating the 101 first block to reach the min confirmations to spend a coinbase utxo.
    debug!(
        &logger,
        "Generating 101 blocks to default address: {}", default_btc_address
    );
    btc_rpc
        .generate_to_address(101, default_btc_address)
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
        // Here we put the max_time_in_queue to 0 because we want the minter to send request right away with no batching
        let minter_id =
            install_minter(&mut minter_canister, ledger_id, &logger, 0, btc_checker_id).await;
        let minter = Principal::from(minter_id.get());
        let ledger = Principal::from(ledger_id.get());

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

        // Get the BTC address of the caller's sub-account 0.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;

        // Let's send some btc to the deposit address
        let btc_to_wrap = 100_000_000_u64;
        send_to_btc_address(&btc_rpc, &logger, &btc_address0, btc_to_wrap).await;

        generate_blocks(
            &btc_rpc,
            &logger,
            BTC_MIN_CONFIRMATIONS,
            default_btc_address,
        );

        // Waiting for the minter to see new utxos
        wait_for_update_balance(&minter_agent, &logger, Some(subaccount0)).await;

        let withdrawal_account = minter_agent
            .get_withdrawal_account()
            .await
            .expect("Error while calling get_withdrawal_account");

        let transfer_amount = btc_to_wrap - BITCOIN_NETWORK_TRANSFER_FEE - CHECK_FEE - TRANSFER_FEE;

        let transfer_result = ledger_agent
            .transfer(TransferArg {
                from_subaccount: Some(subaccount0),
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

        let destination_btc_address = btc_rpc.get_new_address().unwrap();

        info!(&logger, "Call retrieve_btc");

        let retrieve_amount = 500_000 - TRANSFER_FEE;
        let retrieve_response = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: retrieve_amount,
                address: destination_btc_address.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc")
            .expect("Error in retrieve_btc");

        let retrieve_status = minter_agent
            .retrieve_btc_status(retrieve_response.block_index)
            .await
            .expect("failed to call retrieve_btc_status");

        assert!(
            matches!(
                retrieve_status,
                RetrieveBtcStatus::Pending
                    | RetrieveBtcStatus::Signing
                    | RetrieveBtcStatus::Sending { .. }
                    | RetrieveBtcStatus::Submitted { .. }
            ),
            "Expected status Submitted or Pending, got {retrieve_status:?}",
        );

        // Wait for tx to be signed
        let txid = wait_for_signed_tx(&minter_agent, &logger, retrieve_response.block_index).await;
        let txid_bytes: [u8; 32] = txid.into();
        // We wait for the heartbeat to send the transaction to the mempool
        info!(&logger, "Waiting for tx to appear in mempool");
        let mempool_txids = wait_for_mempool_change(&btc_rpc, &logger).await;
        let btc_txid = Txid::from_raw_hash(Hash::from_slice(&txid_bytes).unwrap());
        // Check if we have the txid in the bitcoind mempool
        assert!(
            mempool_txids.contains(&btc_txid),
            "The mempool does not contain the expected txid: {btc_txid}, mempool contents: {mempool_txids:?}"
        );

        // We are expecting only one transaction in mempool.
        assert_eq!(mempool_txids.len(), 1);

        let get_tx_infos = btc_rpc
            .get_mempool_entry(&mempool_txids[0])
            .expect("failed to get tx infos");

        // Check that we have the expected fee
        // We expect this fee because :
        // - the transaction len should be 141 vbytes
        // - a fee of 5 satoshis/vbytes
        // Hence a total fee of 705 satoshis
        const EXPECTED_FEE: u64 = 705;
        assert_eq!(get_tx_infos.fees.base.to_sat(), EXPECTED_FEE);

        // Check that we can modify the fee
        assert!(get_tx_infos.bip125_replaceable);

        #[cfg(feature = "tla")]
        fetch_and_check_traces(minter_canister.clone(), runtime.as_ref());

        // Try to retrieve btc to minter's main_address
        let main_btc_address = minter_agent
            .get_btc_address(Some(minter_id.get().into()), None)
            .await
            .unwrap();
        info!(&logger, "minter's btc main address: {}", main_btc_address);

        let retrieve_amount = 500_000 - TRANSFER_FEE;
        let illegal_retrieve_response = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: retrieve_amount,
                address: main_btc_address.clone(),
            })
            .await;
        assert!(illegal_retrieve_response.is_err());

        // Generate more blocks and wait for the minter to finalize the retrieval.
        generate_blocks(
            &btc_rpc,
            &logger,
            BTC_MIN_CONFIRMATIONS,
            default_btc_address,
        );

        let finalized_txid = wait_for_finalization(
            &btc_rpc,
            &minter_agent,
            &logger,
            retrieve_response.block_index,
            default_btc_address,
        )
        .await;
        assert_eq!(txid, finalized_txid);

        // Check minter's event log
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
                EventType::AcceptedRetrieveBtcRequest(RetrieveBtcRequest {
                    block_index,
                    ..
                }) if *block_index == retrieve_response.block_index
            )),
            "missing the retrieve request in the event log: {events:?}"
        );

        assert!(
            events.iter().any(
                |e| matches!(e, EventType::SentBtcTransaction { txid, .. } if txid == &finalized_txid)
            ),
            "missing the tx submission in the event log: {events:?}"
        );

        assert!(
            events.iter().any(
                |e| matches!(e, EventType::ConfirmedBtcTransaction { txid } if txid == &finalized_txid)
            ),
            "missing the tx confirmation in the event log: {events:?}"
        );
    })
}
fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(TIMEOUT_PER_TEST)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(ckbtc_setup)
        .add_test(systest!(test_deposit_and_withdrawal))
        .execute_from_args()?;
    Ok(())
}
