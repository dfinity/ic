use bitcoin::{consensus::encode::deserialize, Address, Amount, Block};
use bitcoincore_rpc::{bitcoincore_rpc_json::CreateRawTransactionInput, Auth, Client, RpcApi};
use bitcoind::{BitcoinD, Conf, P2P};
use ic_btc_adapter::{
    config::{Config, IncomingSource},
    start_grpc_server_and_router, AdapterState,
};
use ic_btc_adapter_client::setup_bitcoin_adapter_clients;
use ic_btc_interface::Network;
use ic_btc_types_internal::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper, GetSuccessorsRequestInitial,
    SendTransactionRequest,
};
use ic_config::adapters::AdaptersConfig;
use ic_interfaces_adapter_client::{Options, RpcAdapterClient, RpcError};
use ic_logger::{replica_logger::no_op_logger, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4},
    path::Path,
    str::FromStr,
};
use tempfile::{Builder, TempPath};
use tokio::runtime::Runtime;

type BitcoinAdapterClient = Box<
    dyn RpcAdapterClient<BitcoinAdapterRequestWrapper, Response = BitcoinAdapterResponseWrapper>,
>;

fn make_get_successors_request(
    adapter_client: &BitcoinAdapterClient,
    anchor: Vec<u8>,
    headers: Vec<Vec<u8>>,
) -> Result<BitcoinAdapterResponseWrapper, ic_interfaces_adapter_client::RpcError> {
    let request = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
        network: Network::Regtest,
        anchor,
        processed_block_hashes: headers,
    });

    adapter_client.send_blocking(request, Options::default())
}

fn make_send_tx_request(
    adapter_client: &BitcoinAdapterClient,
    raw_tx: &[u8],
) -> Result<BitcoinAdapterResponseWrapper, ic_interfaces_adapter_client::RpcError> {
    let request = BitcoinAdapterRequestWrapper::SendTransactionRequest(SendTransactionRequest {
        network: Network::Regtest,
        transaction: raw_tx.to_vec(),
    });

    adapter_client.send_blocking(request, Options::default())
}

async fn start_adapter(
    logger: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    nodes: Vec<SocketAddr>,
    uds_path: &Path,
) {
    let config = Config {
        network: bitcoin::Network::Regtest,
        incoming_source: IncomingSource::Path(uds_path.to_path_buf()),
        nodes,
        ipv6_only: true,
        ..Default::default()
    };

    let adapter_state = AdapterState::new(config.idle_seconds);

    // make sure that the adapter is not idle
    adapter_state.received_now();

    start_grpc_server_and_router(&config, &metrics_registry, logger, adapter_state);
}

fn get_default_bitcoind() -> BitcoinD {
    let mut conf = Conf::default();
    conf.p2p = P2P::Yes;

    let path =
        std::env::var("BITCOIN_CORE_PATH").expect("Failed to get bitcoin core path env variable");

    bitcoind::BitcoinD::with_conf(path, &conf).unwrap()
}

async fn start_client(
    metrics_registry: MetricsRegistry,
    logger: ReplicaLogger,
    uds_path: &Path,
) -> BitcoinAdapterClient {
    let adapters_config = AdaptersConfig {
        bitcoin_mainnet_uds_path: Some(uds_path.into()),
        bitcoin_mainnet_uds_metrics_path: None,
        bitcoin_testnet_uds_path: None,
        bitcoin_testnet_uds_metrics_path: None,
        https_outcalls_uds_path: None,
        https_outcalls_uds_metrics_path: None,
    };

    setup_bitcoin_adapter_clients(
        logger,
        &metrics_registry,
        tokio::runtime::Handle::current(),
        adapters_config,
    )
    .btc_mainnet_client
}

fn check_received_blocks(client: &Client, blocks: &[Vec<u8>], start_index: usize) {
    for (h, block) in blocks.iter().enumerate() {
        assert_eq!(
            *block,
            client.get_block_hash((start_index + h + 1) as u64).unwrap()[..].to_vec()
        );
    }
}

fn get_bitcoind_url(bitcoind: &BitcoinD) -> Option<SocketAddrV4> {
    if let P2P::Connect(url, _) = bitcoind.p2p_connect(true).unwrap() {
        Some(url)
    } else {
        None
    }
}

fn start_adapter_and_client(
    rt: &Runtime,
    urls: Vec<SocketAddr>,
    logger: ReplicaLogger,
) -> (BitcoinAdapterClient, TempPath) {
    Builder::new()
        .make(|uds_path| {
            Ok(rt.block_on(async {
                let metrics_registry = MetricsRegistry::new();

                start_adapter(
                    logger.clone(),
                    metrics_registry.clone(),
                    urls.clone(),
                    uds_path,
                )
                .await;

                start_client(metrics_registry, logger.clone(), uds_path).await
            }))
        })
        .unwrap()
        .into_parts()
}

fn wait_for_blocks(client: &Client, blocks: u64) {
    let mut tries = 0;
    while client.get_blockchain_info().unwrap().blocks != blocks {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
        if tries > 5 {
            panic!("Timeout in wait_for_blocks");
        }
    }
}

fn wait_for_connection(client: &Client, connection_count: usize) {
    let mut tries = 0;
    while client.get_connection_count().unwrap() != connection_count {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
        if tries > 5 {
            panic!("Timeout in wait_for_connection");
        }
    }
}

fn sync_until_end_block(
    adapter_client: &BitcoinAdapterClient,
    client: &Client,
    start_index: u64,
    headers: &mut Vec<Vec<u8>>,
    max_tries: u64,
) -> Vec<Block> {
    let mut blocks = vec![];
    let mut anchor = client.get_block_hash(start_index).unwrap()[..].to_vec();
    let mut tries = 0;

    let end_hash = client.get_best_block_hash().unwrap()[..].to_vec();
    while anchor != end_hash && tries < max_tries {
        let res = make_get_successors_request(adapter_client, anchor.clone(), headers.clone());
        match res {
            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(res)) => {
                let new_blocks = res.blocks;
                if !new_blocks.is_empty() {
                    let new_headers: Vec<Vec<u8>> = new_blocks
                        .iter()
                        .map(|block| deserialize::<Block>(block).unwrap().block_hash()[..].to_vec())
                        .collect();

                    check_received_blocks(
                        client,
                        &new_headers,
                        start_index as usize + blocks.len(),
                    );

                    headers.extend(new_headers);

                    blocks.extend(new_blocks.iter().map(|block| deserialize(block).unwrap()));
                    anchor = headers.last().unwrap().clone();
                }
            }
            Ok(BitcoinAdapterResponseWrapper::SendTransactionResponse(_)) => {
                panic!("Wrong type of response")
            }
            Err(RpcError::Unavailable(_)) => (), // Adapter still syncing headers
            Err(err) => panic!("{:?}", err),
        }
        tries += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    blocks
}

fn sync_blocks(
    adapter_client: &BitcoinAdapterClient,
    headers: &mut Vec<Vec<u8>>,
    anchor: Vec<u8>,
    len: usize,
    max_tries: u64,
) -> Vec<Block> {
    let mut blocks = vec![];

    let mut tries = 0;
    while blocks.len() < len && tries < max_tries {
        let res = make_get_successors_request(adapter_client, anchor.clone(), headers.clone());
        match res {
            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(res)) => {
                let new_blocks = res.blocks;
                if !new_blocks.is_empty() {
                    let new_headers: Vec<Vec<u8>> = new_blocks
                        .iter()
                        .map(|block| deserialize::<Block>(block).unwrap().block_hash()[..].to_vec())
                        .collect();

                    headers.extend(new_headers);

                    blocks.extend(new_blocks.iter().map(|block| deserialize(block).unwrap()));
                }
            }
            Ok(BitcoinAdapterResponseWrapper::SendTransactionResponse(_)) => {
                panic!("Wrong type of response")
            }
            Err(RpcError::Unavailable(_)) => (), // Adapter still syncing headers
            Err(err) => panic!("{:?}", err),
        }
        tries += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    blocks
}

fn get_blackhole_address() -> Address {
    Address::from_str("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn").unwrap()
}

fn create_alice_and_bob_wallets(bitcoind: &BitcoinD) -> (Client, Client, Address, Address) {
    let alice_client = Client::new(
        format!("{}/wallet/{}", bitcoind.rpc_url(), "alice").as_str(),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
    .unwrap();
    alice_client
        .create_wallet("alice", None, None, None, None)
        .unwrap();

    let bob_client = Client::new(
        format!("{}/wallet/{}", bitcoind.rpc_url(), "bob").as_str(),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
    .unwrap();
    bob_client
        .create_wallet("bob", None, None, None, None)
        .unwrap();

    let alice_address = alice_client.get_new_address(None, None).unwrap();
    let bob_address = bob_client.get_new_address(None, None).unwrap();

    (alice_client, bob_client, alice_address, bob_address)
}

fn fund_with_btc(to_fund_client: &Client, to_fund_address: &Address) {
    let initial_amount = to_fund_client
        .get_received_by_address(to_fund_address, Some(0))
        .unwrap()
        .as_btc();

    to_fund_client
        .generate_to_address(1, to_fund_address)
        .unwrap();

    // Generate 100 blocks for coinbase maturity
    to_fund_client
        .generate_to_address(100, &get_blackhole_address())
        .unwrap();

    // The reward for mining a block is 50 bitcoins
    assert_eq!(
        to_fund_client
            .get_received_by_address(to_fund_address, Some(0))
            .unwrap(),
        Amount::from_btc(initial_amount + 50.0).unwrap()
    );
}

/// Checks that the client (replica) receives the mined blocks using the gRPC service.
#[test]
fn test_receives_blocks() {
    let logger = no_op_logger();
    let bitcoind = get_default_bitcoind();
    let client = Client::new(
        bitcoind.rpc_url().as_str(),
        Auth::CookieFile(bitcoind.params.cookie_file.clone()),
    )
    .unwrap();

    assert_eq!(0, client.get_blockchain_info().unwrap().blocks);

    let address = client.get_new_address(None, None).unwrap();

    client.generate_to_address(150, &address).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    let (adapter_client, _path) = start_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(get_bitcoind_url(&bitcoind).unwrap())],
        logger,
    );

    let blocks = sync_until_end_block(&adapter_client, &client, 0, &mut vec![], 15);

    assert_eq!(blocks.len(), 150);
}

/// Checks that the adapter can connect to multiple BitcoinD peers.
#[test]
fn test_connection_to_multiple_peers() {
    let logger = no_op_logger();

    let bitcoind1 = get_default_bitcoind();
    let client1 = Client::new(
        bitcoind1.rpc_url().as_str(),
        Auth::CookieFile(bitcoind1.params.cookie_file.clone()),
    )
    .unwrap();

    let bitcoind2 = get_default_bitcoind();
    let client2 = Client::new(
        bitcoind2.rpc_url().as_str(),
        Auth::CookieFile(bitcoind2.params.cookie_file.clone()),
    )
    .unwrap();

    let bitcoind3 = get_default_bitcoind();
    let client3 = Client::new(
        bitcoind3.rpc_url().as_str(),
        Auth::CookieFile(bitcoind3.params.cookie_file.clone()),
    )
    .unwrap();

    let url1 = SocketAddr::V4(get_bitcoind_url(&bitcoind1).unwrap());
    let url2 = SocketAddr::V4(get_bitcoind_url(&bitcoind2).unwrap());
    let url3 = SocketAddr::V4(get_bitcoind_url(&bitcoind3).unwrap());

    client1
        .add_node(&url2.to_string())
        .expect("Failed to connect to peer");
    client2
        .add_node(&url3.to_string())
        .expect("Failed to connect to peer");
    client3
        .add_node(&url1.to_string())
        .expect("Failed to connect to peer");

    wait_for_connection(&client1, 2);
    wait_for_connection(&client2, 2);
    wait_for_connection(&client3, 2);

    assert_eq!(client1.get_connection_count().unwrap(), 2);
    assert_eq!(client2.get_connection_count().unwrap(), 2);
    assert_eq!(client3.get_connection_count().unwrap(), 2);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _temp = Builder::new()
        .make(|uds_path| {
            rt.block_on(async {
                start_adapter(
                    logger.clone(),
                    MetricsRegistry::new(),
                    vec![url1, url2, url3],
                    uds_path,
                )
                .await;
            });
            Ok(())
        })
        .unwrap();

    wait_for_connection(&client1, 3);
    wait_for_connection(&client2, 3);
    wait_for_connection(&client3, 3);
}

/// The client (replica) receives newly created transactions by 3rd parties using the gRPC service.
#[test]
fn test_receives_new_3rd_party_txs() {
    let logger = no_op_logger();
    let bitcoind = get_default_bitcoind();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(get_bitcoind_url(&bitcoind).unwrap())],
        logger,
    );

    let (alice_client, bob_client, alice_address, bob_address) =
        create_alice_and_bob_wallets(&bitcoind);

    fund_with_btc(&alice_client, &alice_address);

    assert_eq!(101, alice_client.get_blockchain_info().unwrap().blocks);
    let txid = alice_client
        .send_to_address(
            &bob_address,
            Amount::from_btc(1.0).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("Failed to send to Bob");
    assert_eq!(101, alice_client.get_blockchain_info().unwrap().blocks);
    alice_client
        .generate_to_address(1, &get_blackhole_address())
        .unwrap();
    assert_eq!(102, alice_client.get_blockchain_info().unwrap().blocks);

    let alice_balance = alice_client.get_balance(None, None).unwrap();

    // Take the tx fee into consideration
    assert!(
        alice_balance < Amount::from_btc(49.0).unwrap()
            && alice_balance > Amount::from_btc(48.999).unwrap()
    );
    assert_eq!(
        bob_client.get_balance(None, None).unwrap(),
        Amount::from_btc(1.0).unwrap()
    );

    let blocks = sync_until_end_block(&adapter_client, &alice_client, 101, &mut vec![], 15);

    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].txdata.iter().any(|tx| tx.txid() == txid));
}

/// Ensures the client (replica) can send a transaction (1 BTC from Alice to Bob) using the gRPC service.
#[test]
fn test_send_tx() {
    let logger = no_op_logger();
    let bitcoind = get_default_bitcoind();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(get_bitcoind_url(&bitcoind).unwrap())],
        logger,
    );

    let (alice_client, bob_client, alice_address, bob_address) =
        create_alice_and_bob_wallets(&bitcoind);

    fund_with_btc(&alice_client, &alice_address);

    let to_send = Amount::from_btc(1.0).unwrap();
    let tx_fee = Amount::from_btc(0.001).unwrap();

    let unspent = alice_client
        .list_unspent(None, None, None, None, None)
        .unwrap();
    let utxo = unspent
        .iter()
        .find(|utxo| utxo.amount > to_send + tx_fee)
        .expect("Not enough BTC in Alice's wallet");

    let raw_tx_input = CreateRawTransactionInput {
        txid: utxo.txid,
        vout: utxo.vout,
        sequence: None,
    };

    let mut outs = HashMap::new();
    let change = utxo.amount - to_send - tx_fee;
    outs.insert(bob_address.to_string(), to_send);
    if change > Amount::from_btc(0.0).unwrap() {
        outs.insert(alice_address.to_string(), change);
    }

    let raw_tx = alice_client
        .create_raw_transaction(&[raw_tx_input], &outs, None, Some(true))
        .expect("Failed to create raw transaction");

    let signed_tx = alice_client
        .sign_raw_transaction_with_wallet(&raw_tx, None, None)
        .unwrap();

    let res = make_send_tx_request(&adapter_client, &signed_tx.hex);

    let mut tries = 0;
    while tries < 5
        && bob_client.get_balances().unwrap().mine.untrusted_pending
            == Amount::from_btc(0.0).unwrap()
    {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
    }

    if let BitcoinAdapterResponseWrapper::SendTransactionResponse(_) = res.unwrap() {
        assert_eq!(
            bob_client.get_balances().unwrap().mine.untrusted_pending,
            Amount::from_btc(1.0).unwrap()
        );
    } else {
        panic!("Failed to send transaction");
    }
}

/// Checks that the client (replica) receives blocks from both created forks.
#[test]
fn test_receives_blocks_from_forks() {
    let logger = no_op_logger();
    let bitcoind1 = get_default_bitcoind();
    let client1 = Client::new(
        bitcoind1.rpc_url().as_str(),
        Auth::CookieFile(bitcoind1.params.cookie_file.clone()),
    )
    .unwrap();

    let bitcoind2 = get_default_bitcoind();
    let client2 = Client::new(
        bitcoind2.rpc_url().as_str(),
        Auth::CookieFile(bitcoind2.params.cookie_file.clone()),
    )
    .unwrap();

    let url1 = get_bitcoind_url(&bitcoind1).unwrap();
    let url2 = get_bitcoind_url(&bitcoind2).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(url1), SocketAddr::V4(url2)],
        logger,
    );

    // Connect the nodes and mine some shared blocks
    client1
        .onetry_node(&url2.to_string())
        .expect("Failed to connect to the other peer");

    wait_for_connection(&client1, 2);
    wait_for_connection(&client2, 2);

    let address1 = client1.get_new_address(None, None).unwrap();
    client1.generate_to_address(25, &address1).unwrap();

    wait_for_blocks(&client1, 25);
    wait_for_blocks(&client2, 25);

    let address2 = client2.get_new_address(None, None).unwrap();
    client2.generate_to_address(25, &address2).unwrap();

    wait_for_blocks(&client1, 50);
    wait_for_blocks(&client2, 50);

    // Disconnect the nodes to create a fork
    client1
        .disconnect_node(&url2.to_string())
        .expect("Failed to disconnect peers");

    wait_for_connection(&client1, 1);
    wait_for_connection(&client2, 1);

    client1.generate_to_address(10, &address1).unwrap();
    client2.generate_to_address(15, &address2).unwrap();

    wait_for_blocks(&client1, 60);
    wait_for_blocks(&client2, 65);

    let anchor = client1.get_block_hash(0).unwrap()[..].to_vec();
    let blocks = sync_blocks(&adapter_client, &mut vec![], anchor, 75, 200);
    assert_eq!(blocks.len(), 75);
}
