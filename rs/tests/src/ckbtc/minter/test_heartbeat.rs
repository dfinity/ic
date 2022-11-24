use crate::ckbtc::minter::utils::{
    ensure_wallet, generate_blocks, get_btc_address, get_btc_client, send_to_btc_address,
    wait_for_mempool_change, wait_for_signed_tx, wait_for_update_balance, BTC_MIN_CONFIRMATIONS,
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
use bitcoincore_rpc::{
    bitcoin::{hashes::Hash, Txid},
    RpcApi,
};
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::state::RetrieveBtcStatus;
use ic_ckbtc_minter::updates::get_withdrawal_account::compute_subaccount;
use ic_ckbtc_minter::updates::retrieve_btc::RetrieveBtcArgs;
use ic_icrc1::endpoints::TransferArg;
use ic_icrc1_agent::Icrc1Agent;
use slog::{debug, info};

pub fn test_heartbeat(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;
    let btc_rpc = get_btc_client(&env);
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
        let runtime = runtime_from_url(node.get_public_url());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let minting_user = minter_canister.canister_id().get();
        let ledger_id = install_ledger(&env, &mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&env, &mut minter_canister, ledger_id, &logger).await;
        let minter = Principal::from(minter_id.get());
        let ledger = Principal::from(ledger_id.get());
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        let _universal_canister =
            UniversalCanister::new(&agent, node.effective_canister_id()).await;
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

        // Get the BTC address of the caller's sub-account 0.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;

        // Let's send some btc to the deposit address
        let btc_to_wrap = 100_000_000_u64;
        send_to_btc_address(&btc_rpc, &logger, &btc_address0, btc_to_wrap).await;

        generate_blocks(
            &btc_rpc,
            &logger,
            BTC_MIN_CONFIRMATIONS,
            &default_btc_address,
        );

        // Waiting for the minter to see new utxos
        wait_for_update_balance(&minter_agent, &logger, Some(subaccount0)).await;

        let withdrawal_account = minter_agent
            .get_withdrawal_account()
            .await
            .expect("Error while calling get_withdrawal_account")
            .account;

        const TRANSFER_FEE: u64 = 1_000;

        let transfer_amount = 99_997_180_u64 - TRANSFER_FEE;

        let transfer_result = ledger_agent
            .transfer(TransferArg {
                from_subaccount: Some(subaccount0),
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

        let destination_btc_address = btc_rpc.get_new_address(None, None).unwrap();

        info!(&logger, "Call retrieve_btc");

        let retrieve_amount = 99_997_180_u64 - TRANSFER_FEE;
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
            "Expected status Submitted or Pending, got {:?}",
            retrieve_status,
        );

        // Wait for tx to be signed
        let txid = wait_for_signed_tx(&minter_agent, &logger, retrieve_response.block_index).await;

        // We wait for the heartbeat to send the transaction to the mempool
        info!(&logger, "Waiting for tx to appear in mempool");
        let mempool_txids = wait_for_mempool_change(&btc_rpc, &logger).await;

        let btc_txid = Txid::from_hash(Hash::from_slice(&txid).unwrap());
        // Check if we have the txid in the bitcoind mempool
        assert!(
            mempool_txids.contains(&btc_txid),
            "The mempool does not contain the expected txid: {}, mempool contents: {:?}",
            btc_txid,
            mempool_txids
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
        assert_eq!(get_tx_infos.fees.base.as_sat(), EXPECTED_FEE);

        // Check that we can modify the fee
        assert!(get_tx_infos.bip125_replaceable);
    })
}
