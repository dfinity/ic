use anyhow::Result;

use bitcoincore_rpc::{
    bitcoin::{hashes::Hash, Txid},
    RpcApi,
};
use candid::{CandidType, Deserialize, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::state::RetrieveBtcStatus;
use ic_ckbtc_minter::updates::get_withdrawal_account::compute_subaccount;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    systest,
    util::{assert_create_agent, block_on, runtime_from_url},
};
use ic_tests_ckbtc::{
    activate_ecdsa_signature, create_canister_at_id, install_bitcoin_canister, install_ledger,
    install_minter, install_new_kyt, setup, subnet_sys,
    utils::{
        ensure_wallet, generate_blocks, get_btc_address, get_btc_client, retrieve_btc,
        send_to_btc_address, wait_for_finalization_no_new_blocks, wait_for_mempool_change,
        wait_for_update_balance,
    },
    BTC_MIN_CONFIRMATIONS, KYT_FEE, TEST_KEY_LOCAL, TRANSFER_FEE,
};
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use serde::Serialize;
use serde_bytes::ByteBuf;
use slog::{debug, info};
use std::time::{Duration, Instant};

pub const SHORT_TIMEOUT: Duration = Duration::from_secs(300);

pub const RETRIEVE_REQUESTS_COUNT_TO_BATCH: usize = 20;

#[derive(Clone, Debug, CandidType, Serialize)]
struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: ByteBuf,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: ByteBuf,
}

pub fn test_batching(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
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

    let minter_id = CanisterId::from_u64(200);
    let ledger_id = CanisterId::from_u64(201);
    let new_kyt_id = CanisterId::from_u64(203);

    block_on(async {
        let runtime = runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
        install_bitcoin_canister(&runtime, &logger).await;

        let mut ledger_canister = create_canister_at_id(&runtime, ledger_id.get()).await;
        let mut minter_canister = create_canister_at_id(&runtime, minter_id.get()).await;
        let mut new_kyt_canister = create_canister_at_id(&runtime, new_kyt_id.get()).await;

        let minting_user = minter_canister.canister_id().get();
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let new_kyt_id = install_new_kyt(&mut new_kyt_canister, &env).await;
        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;

        // We set the minter with a very long time in the queue parameter so we can add up requests in queue
        const SEC_NANOS: u64 = 1_000_000_000;
        const MIN_NANOS: u64 = 60 * SEC_NANOS;
        let five_hours_nanos = 300 * MIN_NANOS;
        let minter_id = install_minter(
            &mut minter_canister,
            ledger_id,
            &logger,
            five_hours_nanos,
            new_kyt_id,
        )
        .await;

        let minter = Principal::from(minter_id.get());
        let ledger = Principal::from(ledger_id.get());

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

        wait_for_update_balance(&minter_agent, &logger, Some(subaccount0)).await;

        let withdrawal_account = minter_agent
            .get_withdrawal_account()
            .await
            .expect("Error while calling get_withdrawal_account");

        const BITCOIN_NETWORK_TRANSFER_FEE: u64 = 2820;

        let transfer_amount = btc_to_wrap - BITCOIN_NETWORK_TRANSFER_FEE - KYT_FEE - TRANSFER_FEE;

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

        let destination_btc_address = btc_rpc.get_new_address(None, None).unwrap();

        info!(&logger, "Call retrieve_btc");

        let retrieve_amount = 10_000_u64;
        let mut k = 0_usize;
        let start = Instant::now();
        let mut block_indexes: Vec<u64> = vec![];

        // Let's make multiple retrieve_btc and save the block indices.
        while k != RETRIEVE_REQUESTS_COUNT_TO_BATCH - 1 {
            if start.elapsed() >= SHORT_TIMEOUT {
                panic!("update_balance timeout");
            };
            if let Some(block_index) = retrieve_btc(
                &minter_agent,
                &logger,
                retrieve_amount,
                destination_btc_address.to_string(),
            )
            .await
            {
                block_indexes.push(block_index);
                k += 1;
            }
        }

        assert_eq!(
            block_indexes,
            (2_u64..(RETRIEVE_REQUESTS_COUNT_TO_BATCH as u64 + 1)).collect::<Vec<u64>>()
        );

        // Check that we don't have any tx in the mempool
        let start = Instant::now();
        loop {
            if start.elapsed() >= SHORT_TIMEOUT {
                panic!("No new utxos in mempool timeout");
            };
            match btc_rpc.get_raw_mempool() {
                Ok(r) => {
                    assert!(r.is_empty());
                    break;
                }
                Err(e) => {
                    info!(
                        &logger,
                        "[btc rpc] error while calling mempool {}",
                        e.to_string()
                    );
                }
            };
        }

        // Check the status of all of the submitted requests
        for block_index in block_indexes.iter() {
            assert_eq!(
                minter_agent
                    .retrieve_btc_status(*block_index)
                    .await
                    .expect("failed to call retrieve_btc_status"),
                RetrieveBtcStatus::Pending
            );
        }

        // Let's submit one more tx, this should trigger the transaction batching
        retrieve_btc(
            &minter_agent,
            &logger,
            retrieve_amount,
            destination_btc_address.to_string(),
        )
        .await;

        // Let's wait for the transaction to appear on the mempool
        let mempool_txids = wait_for_mempool_change(&btc_rpc, &logger).await;
        let txid = mempool_txids[0];
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
        // You can use the following estimator : https://btc.network/estimate
        // 1 input and 21 outputs (20 requests and the minter's address)
        // The fee for the demo is 5 sat/vbyte
        // Hence, we expect the fee to be 3650
        // By checking the fee we know that we have the right amount of inputs and outputs
        const EXPECTED_FEE: u64 = 3650;
        assert_eq!(get_tx_infos.fees.base.as_sat(), EXPECTED_FEE);

        // Check that we can modify the fee
        assert!(get_tx_infos.bip125_replaceable);

        // Generate more blocks and wait for the minter to finalize the retrieval.
        generate_blocks(
            &btc_rpc,
            &logger,
            BTC_MIN_CONFIRMATIONS,
            &default_btc_address,
        );

        let finalized_txid =
            wait_for_finalization_no_new_blocks(&minter_agent, block_indexes[0]).await;
        // We don't need to check which input has been used as there is only one input in the possession of the minter
        let txid_array: [u8; 32] = txid.as_hash().to_vec().try_into().unwrap();
        assert_eq!(ic_btc_interface::Txid::from(txid_array), finalized_txid);

        // We can now check that the destination_btc_address received some utxos
        let unspent_result = btc_rpc
            .list_unspent(
                Some(6),
                None,
                Some(&[&destination_btc_address]),
                Some(true),
                None,
            )
            .expect("failed to get tx infos");
        let destination_balance = unspent_result
            .iter()
            .map(|entry| entry.amount.as_sat())
            .sum::<u64>();

        // We have 1 input and 21 outputs (20 requests and the minter's address)
        // Hence, we can compute the minter's fee
        let minters_fee: u64 = ic_ckbtc_minter::MINTER_FEE_PER_INPUT
            + ic_ckbtc_minter::MINTER_FEE_PER_OUTPUT
                * (RETRIEVE_REQUESTS_COUNT_TO_BATCH as u64 + 1)
            + ic_ckbtc_minter::MINTER_FEE_CONSTANT;

        // We can check that the destination address has received all the bitcoin
        assert_eq!(
            destination_balance,
            (RETRIEVE_REQUESTS_COUNT_TO_BATCH as u64) * retrieve_amount
                - EXPECTED_FEE
                - minters_fee
        );

        // We also check that the destination address have received 20 utxos
        assert_eq!(unspent_result.len(), RETRIEVE_REQUESTS_COUNT_TO_BATCH);
    })
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test_batching))
        .execute_from_args()?;
    Ok(())
}
