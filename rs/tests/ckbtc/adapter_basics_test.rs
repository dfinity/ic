use anyhow::Result;
use bitcoin::{Amount, Network as BtcNetwork, dogecoin::Network as DogeNetwork};
use ic_btc_adapter_test_utils::rpc_client::CreateRawTransactionInput;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    systest,
    util::{assert_create_agent, block_on},
};
use ic_tests_ckbtc::{
    IcRpcClientType,
    adapter::{AdapterProxy, fund_with_btc},
    adapter_test_setup, subnet_sys,
    utils::get_rpc_client,
};
use slog::info;
use std::collections::HashMap;

fn test_received_blocks<T: IcRpcClientType>(env: TestEnv) {
    let log = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    // Setup client
    let client = get_rpc_client::<T>(&env);
    let start_height = client.get_blockchain_info().unwrap().blocks;
    let anchor = client.get_block_hash(start_height).unwrap()[..].to_vec();
    info!(log, "Set up bitcoind wallet");

    // Mine 150 blocks
    let address = client.get_address().unwrap();
    client.generate_to_address(150, address).unwrap();
    info!(log, "Generated 150");

    // Instruct the adapter to sync the blocks
    let blocks = block_on(async {
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let adapter_proxy = AdapterProxy::new(T::REGTEST, &agent, log).await;
        adapter_proxy
            .sync_blocks(&mut vec![], anchor, 150, 15)
            .await
            .expect("Failed to syncronize blocks")
    });

    assert_eq!(blocks.len() as u64, start_height + 150);
    for (h, block) in blocks.iter().enumerate() {
        assert_eq!(
            T::block_hash(block),
            client.get_block_hash((h + 1) as u64).unwrap()
        );
    }
}

fn test_receives_new_3rd_party_txs<T: IcRpcClientType>(env: TestEnv) {
    let log = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    let client = get_rpc_client::<T>(&env);
    let start_height = client.get_blockchain_info().unwrap().blocks;
    let anchor = client.get_block_hash(start_height).unwrap()[..].to_vec();
    info!(log, "Set up bitcoind wallet");

    let alice_client = client.with_account("alice").unwrap();
    let bob_client = client.with_account("bob").unwrap();
    let alice_address = alice_client.get_address().unwrap();
    let bob_address = bob_client.get_address().unwrap();
    info!(log, "Set up alice and bob");

    fund_with_btc(&alice_client, alice_address);

    let alice_balance_initial = alice_client.get_balance(None).unwrap();
    let bob_balance_initial = bob_client.get_balance(None).unwrap();

    let start_height = client.get_blockchain_info().unwrap().blocks;
    let txid = alice_client
        .send_to(
            bob_address,
            Amount::from_btc(1.0).unwrap(),
            Amount::from_btc(0.0001).unwrap(),
        )
        .expect("Failed to send to Bob");
    let blackhole_address = alice_client.get_new_address().unwrap();
    alice_client
        .generate_to_address(1, &blackhole_address)
        .unwrap();
    assert_eq!(
        alice_client.get_blockchain_info().unwrap().blocks,
        start_height + 1
    );

    // Take the tx fee into consideration
    let alice_balance_diff = alice_balance_initial - alice_client.get_balance(None).unwrap();
    let bob_balance_diff = bob_client.get_balance(None).unwrap() - bob_balance_initial;
    assert!(
        alice_balance_diff > Amount::from_btc(1.0).unwrap()
            && alice_balance_diff < Amount::from_btc(1.001).unwrap()
    );
    assert_eq!(bob_balance_diff, Amount::from_btc(1.0).unwrap());

    // Instruct the adapter to sync the blocks
    let blocks = block_on(async {
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let adapter_proxy = AdapterProxy::new(T::REGTEST, &agent, log).await;
        adapter_proxy
            .sync_blocks(&mut vec![], anchor, 102, 15)
            .await
            .expect("Failed to synchronize blocks")
    });

    assert!(T::iter_transactions(blocks.last().unwrap()).any(|tx| tx.compute_txid() == txid));
}

fn test_send_tx<T: IcRpcClientType>(env: TestEnv) {
    let log = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    info!(log, "Set up bitcoind wallet");
    let client = get_rpc_client::<T>(&env);
    let alice_client = client.with_account("alice").unwrap();
    let bob_client = client.with_account("bob").unwrap();
    let alice_address = alice_client.get_address().unwrap();
    let bob_address = bob_client.get_address().unwrap();
    info!(log, "Set up alice and bob");

    let utxo = fund_with_btc(&alice_client, alice_address);

    let to_send = Amount::from_btc(1.0).unwrap();
    let tx_fee = Amount::from_btc(0.001).unwrap();

    let mut outs = HashMap::new();
    let change = utxo.amount - to_send - tx_fee;
    outs.insert(bob_address.to_string(), to_send);
    if change > Amount::from_btc(0.0).unwrap() {
        outs.insert(alice_address.to_string(), change);
    }

    let raw_tx_input = CreateRawTransactionInput {
        txid: utxo.txid,
        vout: utxo.vout,
        sequence: None,
    };

    let raw_tx = alice_client
        .create_raw_transaction(&[raw_tx_input], &outs)
        .expect("Failed to create raw transaction");

    let signed_tx = alice_client.sign_raw_transaction(&raw_tx, None).unwrap();

    assert!(signed_tx.complete);
    assert!(signed_tx.errors.is_none());

    block_on(async {
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let adapter_proxy = AdapterProxy::new(T::REGTEST, &agent, log).await;
        adapter_proxy
            .send_tx(signed_tx.hex)
            .await
            .expect("Failed to send transaction")
    });

    let bob_balance = bob_client.get_balance(None).unwrap();
    let mut tries = 0;
    while tries < 5 && bob_client.get_balance(None).unwrap() == bob_balance {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
    }

    assert_eq!(
        bob_client.get_balance(None).unwrap(),
        Amount::from_btc(1.0).unwrap()
    );
}

fn test<T: 'static + IcRpcClientType>() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(adapter_test_setup::<T>)
        .add_test(systest!(test_received_blocks::<T>))
        .add_test(systest!(test_receives_new_3rd_party_txs::<T>))
        .add_test(systest!(test_send_tx::<T>))
        .execute_from_args()
}

fn main() -> Result<()> {
    let test_name = std::env::var("ADAPTER_TO_TEST")
        .unwrap_or_else(|_| panic!("environment variable ADAPTER_TO_TEST is not set"))
        .to_uppercase();
    if test_name == "BTC" {
        test::<BtcNetwork>()?;
    } else if test_name == "DOGE" {
        test::<DogeNetwork>()?;
    } else {
        panic!("Unsupported ADAPTER_TO_TEST {test_name}");
    }
    Ok(())
}
