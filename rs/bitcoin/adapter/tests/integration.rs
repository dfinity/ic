use bitcoin::{
    Amount, BlockHash, Network as BtcNetwork, consensus::encode::deserialize,
    dogecoin::Network as DogeNetwork,
};
use ic_btc_adapter::{AdapterNetwork, Config, IncomingSource, start_server};
use ic_btc_adapter_client::setup_bitcoin_adapter_clients;
use ic_btc_adapter_test_utils::{
    bitcoind::{Conf, Daemon},
    rpc_client::{CreateRawTransactionInput, RpcClient, RpcClientType},
};
use ic_btc_replica_types::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponseWrapper, GetSuccessorsRequestInitial,
    Network, SendTransactionRequest,
};
use ic_config::bitcoin_payload_builder_config::Config as BitcoinPayloadBuilderConfig;
use ic_config::logger::{Config as LoggerConfig, Level as LoggerLevel};
use ic_interfaces_adapter_client::{Options, RpcAdapterClient, RpcError};
use ic_logger::{ReplicaLogger, replica_logger::no_op_logger};
use ic_metrics::MetricsRegistry;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path,
};
use tempfile::{Builder, TempPath};
use tokio::runtime::Runtime;

type AdapterClient = Box<
    dyn RpcAdapterClient<BitcoinAdapterRequestWrapper, Response = BitcoinAdapterResponseWrapper>,
>;

enum AdapterState {
    Idle,
    Active,
}

struct ForkTestData {
    blocks: Vec<BlockHash>,
    exclude_start: usize,
    exclude_stop: usize,
}

impl ForkTestData {
    fn new(blocks: Vec<BlockHash>, exclude_start: usize, exclude_stop: usize) -> Self {
        Self {
            blocks,
            exclude_start,
            exclude_stop,
        }
    }

    fn update_excluded(&mut self, exclude_start: usize, exclude_stop: usize) {
        self.exclude_start = exclude_start;
        self.exclude_stop = exclude_stop;
    }
}

fn make_get_successors_request(
    adapter_client: &AdapterClient,
    anchor: Vec<u8>,
    headers: Vec<Vec<u8>>,
) -> Result<BitcoinAdapterResponseWrapper, ic_interfaces_adapter_client::RpcError> {
    let request = BitcoinAdapterRequestWrapper::GetSuccessorsRequest(GetSuccessorsRequestInitial {
        network: Network::BitcoinRegtest,
        anchor,
        processed_block_hashes: headers,
    });

    adapter_client.send_blocking(
        request,
        Options {
            timeout: BitcoinPayloadBuilderConfig::default().adapter_timeout,
        },
    )
}

fn make_send_tx_request(
    adapter_client: &AdapterClient,
    raw_tx: &[u8],
) -> Result<BitcoinAdapterResponseWrapper, ic_interfaces_adapter_client::RpcError> {
    let request = BitcoinAdapterRequestWrapper::SendTransactionRequest(SendTransactionRequest {
        network: Network::BitcoinRegtest,
        transaction: raw_tx.to_vec(),
    });

    adapter_client.send_blocking(
        request,
        Options {
            timeout: BitcoinPayloadBuilderConfig::default().adapter_timeout,
        },
    )
}

fn start_adapter<T: RpcClientType + Into<AdapterNetwork>>(
    logger: ReplicaLogger,
    metrics_registry: MetricsRegistry,
    rt_handle: &tokio::runtime::Handle,
    nodes: Vec<SocketAddr>,
    uds_path: &Path,
    network: T,
) {
    let config = Config {
        incoming_source: IncomingSource::Path(uds_path.to_path_buf()),
        nodes,
        ipv6_only: true,
        address_limits: (1, 1),
        idle_seconds: 6, // it can take at most 5 seconds for tcp connections etc to be established.
        ..Config::default_with(network.into())
    };
    let _enter = rt_handle.enter();
    rt_handle.spawn(start_server(logger, metrics_registry, config));
}

fn start_bitcoind<T: RpcClientType>(network: T) -> Daemon<T> {
    let conf = Conf {
        p2p: true,
        view_stdout: true,
        ..Conf::default()
    };
    let name = format!("{}_CORE_PATH", T::NAME.to_uppercase());
    let path = std::env::var(&name).unwrap_or_else(|_| panic!("Failed to get {name} env variable"));

    Daemon::new(&path, network, conf)
}

fn start_client<T: RpcClientType>(
    logger: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: &tokio::runtime::Handle,
    uds_path: &Path,
) -> AdapterClient {
    let adapters_config = T::new_adapters_config_with_mainnet_uds_path(uds_path);
    let clients = setup_bitcoin_adapter_clients(
        logger.clone(),
        metrics_registry,
        rt_handle.clone(),
        adapters_config,
    );
    if T::NAME == BtcNetwork::NAME {
        clients.btc_mainnet_client
    } else if T::NAME == DogeNetwork::NAME {
        clients.doge_mainnet_client
    } else {
        unreachable!()
    }
}

fn check_received_blocks<T: RpcClientType>(
    client: &RpcClient<T>,
    blocks: &[Vec<u8>],
    start_index: usize,
) {
    for (h, block) in blocks.iter().enumerate() {
        assert_eq!(
            *block,
            client.get_block_hash((start_index + h + 1) as u64).unwrap()[..].to_vec()
        );
    }
}

fn start_adapter_and_client<T: RpcClientType + Into<AdapterNetwork>>(
    rt: &Runtime,
    urls: Vec<SocketAddr>,
    logger: ReplicaLogger,
    network: T,
    adapter_state: AdapterState,
) -> (AdapterClient, TempPath) {
    let metrics_registry = MetricsRegistry::new();
    let res = Builder::new()
        .make(|uds_path| {
            start_adapter(
                logger.clone(),
                metrics_registry.clone(),
                rt.handle(),
                urls.clone(),
                uds_path,
                network,
            );
            Ok(start_client::<T>(
                &logger,
                &metrics_registry,
                rt.handle(),
                uds_path,
            ))
        })
        .unwrap()
        .into_parts();

    let anchor: BlockHash = "0000000000000000035908aacac4c97fb4e172a1758bbbba2ee2b188765780eb"
        .parse()
        .unwrap();
    if let AdapterState::Active = adapter_state {
        // Send this request to make sure the adapter is not idle.
        // Retry until the request goes through, because the adapter may not be fully
        // started yet.
        for _ in 0..10 {
            let res = make_get_successors_request(&res.0, anchor[..].to_vec(), vec![]);
            if res.is_err() {
                std::thread::sleep(std::time::Duration::from_secs(1));
            } else {
                break;
            }
        }
    }

    res
}

fn start_idle_adapter_and_client<T: RpcClientType + Into<AdapterNetwork>>(
    rt: &Runtime,
    urls: Vec<SocketAddr>,
    logger: ReplicaLogger,
    network: T,
) -> (AdapterClient, TempPath) {
    start_adapter_and_client(rt, urls, logger, network, AdapterState::Idle)
}

fn start_active_adapter_and_client<T: RpcClientType + Into<AdapterNetwork>>(
    rt: &Runtime,
    urls: Vec<SocketAddr>,
    logger: ReplicaLogger,
    network: T,
) -> (AdapterClient, TempPath) {
    start_adapter_and_client(rt, urls, logger, network, AdapterState::Active)
}

fn wait_for_blocks<T: RpcClientType>(client: &RpcClient<T>, blocks: u64) {
    let mut tries = 0;
    while client.get_blockchain_info().unwrap().blocks != blocks {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
        if tries > 5 {
            panic!("Timeout in wait_for_blocks");
        }
    }
}

fn wait_for_connection<T: RpcClientType>(client: &RpcClient<T>, connection_count: usize) {
    let mut tries = 0;
    while client.get_connection_count().unwrap() != connection_count {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
        if tries > 5 {
            panic!("Timeout in wait_for_connection");
        }
    }
}

// This is an expensive operation. Should only be used when checking for an upper bound on the number of connections.
fn exact_connections<T: RpcClientType>(client: &RpcClient<T>, connection_count: usize) {
    // It always takes less than 5 seconds for the client to connect to the adapter.
    // TODO: Rethink this. It's not a good idea to have a fixed sleep time. ditto in wait_for_connection
    std::thread::sleep(std::time::Duration::from_secs(5));
    if client.get_connection_count().unwrap() != connection_count {
        panic!(
            "Expected {} connections, got {}",
            connection_count,
            client.get_connection_count().unwrap()
        );
    }
}

fn sync_until_end_block<T: RpcClientType>(
    adapter_client: &AdapterClient,
    client: &RpcClient<T>,
    start_index: u64,
    headers: &mut Vec<Vec<u8>>,
    max_tries: u64,
) -> Vec<T::Block> {
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
                        .map(|block| {
                            (T::block_hash(&deserialize::<T::Block>(block).unwrap()).as_ref()
                                as &[u8])
                                .to_vec()
                        })
                        .collect();

                    check_received_blocks(
                        client,
                        &new_headers,
                        start_index as usize + blocks.len(),
                    );

                    headers.extend(new_headers);

                    blocks.extend(new_blocks.iter().map(|block| deserialize(block).unwrap()));
                    anchor.clone_from(headers.last().unwrap());
                }
            }
            Ok(BitcoinAdapterResponseWrapper::SendTransactionResponse(_))
            | Ok(BitcoinAdapterResponseWrapper::GetSuccessorsReject(_))
            | Ok(BitcoinAdapterResponseWrapper::SendTransactionReject(_)) => {
                panic!("Wrong type of response")
            }
            Err(RpcError::Unavailable(_)) | Err(RpcError::Cancelled(_)) => (), // Adapter still syncing headers or likely a timeout
            Err(err) => panic!("{err:?}"),
        }
        tries += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    blocks
}

fn sync_blocks<T: RpcClientType>(
    adapter_client: &AdapterClient,
    headers: &mut Vec<Vec<u8>>,
    anchor: Vec<u8>,
    max_num_blocks: usize,
    max_tries: u64,
) -> Vec<T::Block> {
    let mut blocks = vec![];

    let mut tries = 0;
    while blocks.len() < max_num_blocks && tries < max_tries {
        let res = make_get_successors_request(adapter_client, anchor.clone(), headers.clone());
        match res {
            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(res)) => {
                let new_blocks = res.blocks;
                if !new_blocks.is_empty() {
                    let new_headers: Vec<Vec<u8>> = new_blocks
                        .iter()
                        .map(|block| {
                            (T::block_hash(&deserialize::<T::Block>(block).unwrap()).as_ref()
                                as &[u8])
                                .to_vec()
                        })
                        .collect();

                    headers.extend(new_headers);

                    blocks.extend(new_blocks.iter().map(|block| deserialize(block).unwrap()));
                }
            }
            Ok(BitcoinAdapterResponseWrapper::SendTransactionResponse(_))
            | Ok(BitcoinAdapterResponseWrapper::GetSuccessorsReject(_))
            | Ok(BitcoinAdapterResponseWrapper::SendTransactionReject(_)) => {
                panic!("Wrong type of response")
            }
            Err(RpcError::Unavailable(_)) | Err(RpcError::Cancelled(_)) => (), // Adapter still syncing headers or likely a timeout
            Err(err) => panic!("{err:?}"),
        }
        tries += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    blocks
}

// Returns once all the blocks are received. If the result is built from multiple calls then we can't properly check the BFS ordering.
fn sync_blocks_at_once<T: RpcClientType>(
    adapter_client: &AdapterClient,
    headers: &[Vec<u8>],
    anchor: Vec<u8>,
    max_num_blocks: usize,
    max_tries: u64,
) -> Vec<T::Block> {
    let mut blocks = vec![];

    let mut tries = 0;
    while blocks.len() < max_num_blocks && tries < max_tries {
        let res = make_get_successors_request(adapter_client, anchor.clone(), headers.to_vec());
        match res {
            Ok(BitcoinAdapterResponseWrapper::GetSuccessorsResponse(res)) => {
                let new_blocks = res.blocks;
                if new_blocks.len() == max_num_blocks {
                    blocks.extend(new_blocks.iter().map(|block| deserialize(block).unwrap()));
                }
            }
            Ok(BitcoinAdapterResponseWrapper::SendTransactionResponse(_))
            | Ok(BitcoinAdapterResponseWrapper::GetSuccessorsReject(_))
            | Ok(BitcoinAdapterResponseWrapper::SendTransactionReject(_)) => {
                panic!("Wrong type of response")
            }
            Err(RpcError::Unavailable(_)) | Err(RpcError::Cancelled(_)) => (), // Adapter still syncing headers or likely a timeout
            Err(err) => panic!("{err:?}"),
        }
        tries += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    blocks
}

fn create_alice_and_bob_wallets<T: RpcClientType>(
    bitcoind: &Daemon<T>,
) -> (RpcClient<T>, RpcClient<T>) {
    let client = &bitcoind.rpc_client;
    let alice_client = client.with_account("alice").unwrap();
    let bob_client = client.with_account("bob").unwrap();
    (alice_client, bob_client)
}

fn fund<T: RpcClientType>(to_fund_client: &RpcClient<T>) {
    let blackhole_address = to_fund_client.get_new_address().unwrap();
    let to_fund_address = to_fund_client.get_address().unwrap();
    let initial_amount = to_fund_client
        .get_balance_of(None, to_fund_address)
        .unwrap();

    to_fund_client
        .generate_to_address(1, to_fund_address)
        .unwrap();

    // Generate enough blocks for coinbase maturity
    to_fund_client
        .generate_to_address(T::REGTEST_COINBASE_MATURITY, &blackhole_address)
        .unwrap();

    // The check below uses `listunspent` internally, which is more reliable than `receivedbyaddress`.
    assert_eq!(
        to_fund_client
            .get_balance_of(None, to_fund_address)
            .unwrap(),
        initial_amount + T::REGTEST_INITIAL_BLOCK_REWARDS,
    );
}

fn make_bfs_order(
    forks: &[Vec<BlockHash>],
    processed_hashes: &HashSet<BlockHash>,
) -> Vec<BlockHash> {
    let mut res = vec![];
    let mut i = 0;
    loop {
        let mut modified = false;
        for fork in forks.iter() {
            if i < fork.len() && !processed_hashes.contains(&fork[i]) {
                modified = true;
                res.push(fork[i]);
            }
        }
        if !modified {
            break;
        } else {
            i += 1;
        }
    }
    res
}

fn check_fork_bfs_order<T: RpcClientType>(
    shared_blocks: &[BlockHash],
    fork1: &ForkTestData,
    fork2: &ForkTestData,
    adapter_client: &AdapterClient,
    anchor: Vec<u8>,
) -> (Vec<BlockHash>, Vec<BlockHash>, Vec<BlockHash>) {
    let mut processed_hashes: HashSet<BlockHash> = HashSet::new();
    processed_hashes.extend(fork1.blocks[fork1.exclude_start..fork1.exclude_stop].to_vec());
    processed_hashes.extend(fork2.blocks[fork2.exclude_start..fork2.exclude_stop].to_vec());
    let mut bfs_order1 = shared_blocks.to_vec();
    let mut bfs_order2 = shared_blocks.to_vec();
    let mut temp1 = make_bfs_order(
        &[fork1.blocks.to_vec(), fork2.blocks.to_vec()],
        &processed_hashes,
    );
    let mut temp2 = make_bfs_order(
        &[fork2.blocks.to_vec(), fork1.blocks.to_vec()],
        &processed_hashes,
    );
    bfs_order1.append(&mut temp1);
    bfs_order2.append(&mut temp2);

    let excluded_amount_fork1 = fork1.exclude_stop - fork1.exclude_start;
    let excluded_amount_fork2 = fork2.exclude_stop - fork2.exclude_start;
    let expected_len = shared_blocks.len() + fork1.blocks.len() + fork2.blocks.len()
        - excluded_amount_fork1
        - excluded_amount_fork2;

    let blocks = sync_blocks_at_once::<T>(
        adapter_client,
        &processed_hashes
            .iter()
            .map(|hash| hash[..].to_vec())
            .collect::<Vec<Vec<u8>>>(),
        anchor,
        expected_len,
        400,
    );
    assert_eq!(blocks.len(), expected_len);
    let block_hashes: Vec<BlockHash> = blocks.iter().map(|block| T::block_hash(block)).collect();

    (block_hashes, bfs_order1, bfs_order2)
}

fn sync_headers_until_checkpoint(adapter_client: &AdapterClient, anchor: Vec<u8>) {
    loop {
        let res = make_get_successors_request(adapter_client, anchor.clone(), vec![]);
        match res {
            Err(RpcError::Unavailable(_)) | Err(RpcError::Cancelled(_)) => {
                // Checkpoint has not been surpassed, adapter still syncing headers
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
            Err(err) => panic!("{err:?}"),
            _ => return,
        }
    }
}

/// Checks that the client (replica) receives the mined blocks using the gRPC service.
fn test_receives_blocks<T: RpcClientType + Into<AdapterNetwork>>() {
    let logger = no_op_logger();
    let network = T::REGTEST;
    let bitcoind = start_bitcoind(network);
    let client = &bitcoind.rpc_client;

    assert_eq!(0, client.get_blockchain_info().unwrap().blocks);

    let address = client.get_address().unwrap();

    client.generate_to_address(150, address).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    let (adapter_client, _path) = start_active_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(bitcoind.p2p_socket().unwrap())],
        logger,
        network,
    );

    let blocks = sync_until_end_block(&adapter_client, client, 0, &mut vec![], 15);

    assert_eq!(blocks.len(), 150);
}

#[test]
fn btc_test_receives_blocks() {
    test_receives_blocks::<BtcNetwork>()
}

#[test]
fn doge_test_receives_blocks() {
    test_receives_blocks::<DogeNetwork>()
}

// Checks that the adapter disconnects from the clients when it becomes idle.
fn test_adapter_disconnects_when_idle<T: RpcClientType + Into<AdapterNetwork>>() {
    let logger = no_op_logger();
    let network = T::REGTEST;
    let bitcoind = start_bitcoind(network);
    let client = &bitcoind.rpc_client;

    let url = SocketAddr::V4(bitcoind.p2p_socket().unwrap());

    let rt: Runtime = tokio::runtime::Runtime::new().unwrap();

    let _r = start_active_adapter_and_client(&rt, vec![url], logger, network);

    // The client should be connected to the adapter
    wait_for_connection(client, 1);

    // it takes 6 seconds for the adapter to become idle (in the test config).
    std::thread::sleep(std::time::Duration::from_secs(7)); // wait for the adapter to become idle.

    // As the adapter is now idle, the connection with the client should be dropped.
    // Hence the client should not have any connections.
    exact_connections(client, 0);
}

#[test]
fn btc_test_adapter_disconnects_when_idle() {
    test_adapter_disconnects_when_idle::<BtcNetwork>()
}

#[test]
fn doge_test_adapter_disconnects_when_idle() {
    test_adapter_disconnects_when_idle::<DogeNetwork>()
}

/// Checks that an idle adapter does not connect to any peers.
fn idle_adapter_does_not_connect_to_peers<T: RpcClientType + Into<AdapterNetwork>>() {
    let logger = no_op_logger();
    let network = T::REGTEST;
    let bitcoind = start_bitcoind(network);
    let client = &bitcoind.rpc_client;

    let url = SocketAddr::V4(bitcoind.p2p_socket().unwrap());

    // The client does not have any connections
    wait_for_connection(client, 0);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let _r = start_idle_adapter_and_client(&rt, vec![url], logger, network);

    // The client still does not have any connections
    exact_connections(client, 0);
}

#[test]
fn btc_idle_adapter_does_not_connect_to_peers() {
    idle_adapter_does_not_connect_to_peers::<BtcNetwork>()
}

#[test]
fn doge_idle_adapter_does_not_connect_to_peers() {
    idle_adapter_does_not_connect_to_peers::<DogeNetwork>()
}

/// Checks that the adapter can connect to multiple peers.
fn test_connection_to_multiple_peers<T: RpcClientType + Into<AdapterNetwork>>() {
    let logger = no_op_logger();
    let network = T::REGTEST;
    let bitcoind1 = start_bitcoind(network);
    let client1 = &bitcoind1.rpc_client;

    let bitcoind2 = start_bitcoind(network);
    let client2 = &bitcoind2.rpc_client;

    let bitcoind3 = start_bitcoind(network);
    let client3 = &bitcoind3.rpc_client;

    let url1 = SocketAddr::V4(bitcoind1.p2p_socket().unwrap());
    let url2 = SocketAddr::V4(bitcoind2.p2p_socket().unwrap());
    let url3 = SocketAddr::V4(bitcoind3.p2p_socket().unwrap());

    client1
        .add_node(&url2.to_string())
        .expect("Failed to connect to peer");
    client2
        .add_node(&url3.to_string())
        .expect("Failed to connect to peer");
    client3
        .add_node(&url1.to_string())
        .expect("Failed to connect to peer");

    wait_for_connection(client1, 2);
    wait_for_connection(client2, 2);
    wait_for_connection(client3, 2);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let _r = start_active_adapter_and_client(&rt, vec![url1, url2, url3], logger, network);

    wait_for_connection(client1, 3);
    wait_for_connection(client2, 3);
    wait_for_connection(client3, 3);
}

#[test]
fn btc_test_connection_to_multiple_peers() {
    test_connection_to_multiple_peers::<BtcNetwork>()
}

#[test]
fn doge_test_connection_to_multiple_peers() {
    test_connection_to_multiple_peers::<DogeNetwork>()
}

/// The client (replica) receives newly created transactions by 3rd parties using the gRPC service.
fn test_receives_new_3rd_party_txs<T: RpcClientType + Into<AdapterNetwork>>() {
    let logger = no_op_logger();
    let network = T::REGTEST;
    let bitcoind = start_bitcoind(network);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_active_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(bitcoind.p2p_socket().unwrap())],
        logger,
        network,
    );

    let (alice_client, bob_client) = create_alice_and_bob_wallets(&bitcoind);
    let blackhole_address = alice_client.get_new_address().unwrap();

    fund(&alice_client);

    assert_eq!(
        T::REGTEST_COINBASE_MATURITY + 1,
        alice_client.get_blockchain_info().unwrap().blocks
    );
    let initial_alice_balance = alice_client.get_balance(None).unwrap();
    let txid = alice_client
        .send_to(
            bob_client.get_address().unwrap(),
            Amount::from_btc(1.0).unwrap(),
            Amount::from_btc(0.001).unwrap(),
        )
        .expect("Failed to send to Bob");
    assert_eq!(
        T::REGTEST_COINBASE_MATURITY + 1,
        alice_client.get_blockchain_info().unwrap().blocks
    );
    alice_client
        .generate_to_address(1, &blackhole_address)
        .unwrap();
    assert_eq!(
        T::REGTEST_COINBASE_MATURITY + 2,
        alice_client.get_blockchain_info().unwrap().blocks
    );

    let alice_balance = alice_client.get_balance(None).unwrap();

    // Take the tx fee into consideration
    assert_eq!(
        alice_balance + Amount::from_btc(1.001).unwrap(),
        initial_alice_balance
    );
    assert_eq!(
        bob_client.get_balance(None).unwrap(),
        Amount::from_btc(1.0).unwrap()
    );

    let blocks = sync_until_end_block(
        &adapter_client,
        &alice_client,
        T::REGTEST_COINBASE_MATURITY + 1,
        &mut vec![],
        15,
    );

    assert_eq!(blocks.len(), 1);
    assert!(T::iter_transactions(&blocks[0]).any(|tx| tx.compute_txid() == txid));
}

#[test]
fn btc_test_receives_new_3rd_party_txs() {
    test_receives_new_3rd_party_txs::<BtcNetwork>()
}

#[test]
fn doge_test_receives_new_3rd_party_txs() {
    test_receives_new_3rd_party_txs::<DogeNetwork>()
}

/// Ensures the client (replica) can send a transaction (1 BTC from Alice to Bob) using the gRPC service.
fn test_send_tx<T: RpcClientType + Into<AdapterNetwork>>() {
    let logger = no_op_logger();
    let network = T::REGTEST;
    let bitcoind = start_bitcoind(network);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_active_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(bitcoind.p2p_socket().unwrap())],
        logger,
        network,
    );

    let (alice_client, bob_client) = create_alice_and_bob_wallets(&bitcoind);

    fund(&alice_client);

    let to_send = Amount::from_btc(1.0).unwrap();
    let tx_fee = Amount::from_btc(0.001).unwrap();

    let unspent = alice_client.list_unspent(None, None).unwrap();
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
    outs.insert(bob_client.get_address().unwrap().to_string(), to_send);
    if change > Amount::from_btc(0.0).unwrap() {
        outs.insert(alice_client.get_address().unwrap().to_string(), change);
    }

    let raw_tx = alice_client
        .create_raw_transaction(&[raw_tx_input], &outs)
        .expect("Failed to create raw transaction");

    let signed_tx = alice_client.sign_raw_transaction(&raw_tx, None).unwrap();

    let res = make_send_tx_request(&adapter_client, &signed_tx.hex);

    let bob_balance = bob_client.get_balance(None).unwrap();
    let mut tries = 0;
    while tries < 5 && bob_client.get_balance(None).unwrap() == bob_balance {
        std::thread::sleep(std::time::Duration::from_secs(1));
        tries += 1;
    }

    if let BitcoinAdapterResponseWrapper::SendTransactionResponse(_) = res.unwrap() {
        assert_eq!(
            bob_client.get_balance(None).unwrap(),
            Amount::from_btc(1.0).unwrap(),
        );
    } else {
        panic!("Failed to send transaction");
    }
}

#[test]
fn btc_test_send_tx() {
    test_send_tx::<BtcNetwork>()
}

#[test]
fn doge_test_send_tx() {
    test_send_tx::<DogeNetwork>()
}

/// Checks that the client (replica) receives blocks from both created forks.
fn test_receives_blocks_from_forks<T: RpcClientType + Into<AdapterNetwork>>() {
    use ic_logger::new_replica_logger_from_config;

    let network = T::REGTEST;
    let bitcoind1 = start_bitcoind(network);
    let client1 = &bitcoind1.rpc_client;

    let bitcoind2 = start_bitcoind(network);
    let client2 = &bitcoind2.rpc_client;

    let url1 = bitcoind1.p2p_socket().unwrap();
    let url2 = bitcoind2.p2p_socket().unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    let logger_config = LoggerConfig {
        level: LoggerLevel::Trace,
        ..LoggerConfig::default()
    };
    let (logger, _async_log_guard) = new_replica_logger_from_config(&logger_config);
    let (adapter_client, _path) = start_active_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(url1), SocketAddr::V4(url2)],
        logger,
        network,
    );

    // Connect the nodes and mine some shared blocks
    client1
        .onetry_node(&url2.to_string())
        .expect("Failed to connect to the other peer");

    wait_for_connection(client1, 2);
    wait_for_connection(client2, 2);

    let address1 = client1.get_address().unwrap();
    client1.generate_to_address(10, address1).unwrap();

    wait_for_blocks(client1, 10);
    wait_for_blocks(client2, 10);

    let address2 = client2.get_address().unwrap();
    client2.generate_to_address(10, address2).unwrap();

    wait_for_blocks(client1, 20);
    wait_for_blocks(client2, 20);

    // Disconnect the nodes to create a fork
    client1
        .disconnect_node(&url2.to_string())
        .expect("Failed to disconnect peers");

    wait_for_connection(client1, 1);
    wait_for_connection(client2, 1);

    client1.generate_to_address(3, address1).unwrap();
    client2.generate_to_address(6, address2).unwrap();

    wait_for_blocks(client1, 23);
    wait_for_blocks(client2, 26);

    let anchor = client1.get_block_hash(0).unwrap()[..].to_vec();
    let blocks = sync_blocks::<T>(&adapter_client, &mut vec![], anchor, 29, 201);
    assert_eq!(blocks.len(), 29);
}

#[test]
fn btc_test_receives_blocks_from_forks() {
    test_receives_blocks_from_forks::<BtcNetwork>()
}

#[test]
fn doge_test_receives_blocks_from_forks() {
    test_receives_blocks_from_forks::<DogeNetwork>()
}

/// Checks that the adapter returns blocks in BFS order.
fn test_bfs_order<T: RpcClientType + Into<AdapterNetwork>>() {
    let logger = no_op_logger();
    let network = T::REGTEST;
    let bitcoind1 = start_bitcoind(network);
    let client1 = &bitcoind1.rpc_client;

    let bitcoind2 = start_bitcoind(network);
    let client2 = &bitcoind2.rpc_client;

    let url1 = bitcoind1.p2p_socket().unwrap();
    let url2 = bitcoind2.p2p_socket().unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) = start_active_adapter_and_client(
        &rt,
        vec![SocketAddr::V4(url1), SocketAddr::V4(url2)],
        logger,
        network,
    );

    // Connect the nodes and mine some shared blocks
    client1
        .onetry_node(&url2.to_string())
        .expect("Failed to connect to the other peer");

    wait_for_connection(client1, 2);
    wait_for_connection(client2, 2);

    let address1 = client1.get_address().unwrap();
    // IMPORTANT:
    // Increasing the number of blocks in this test could lead to flakiness due to the number of "request rounds"
    // alligning with the round robin of the adapter's peers. Currently all blocks are tried and retried in a single round.
    let shared_blocks_count = 2;
    let branch_length = 6;
    let shared_blocks = client1
        .generate_to_address(shared_blocks_count, address1)
        .unwrap();

    wait_for_blocks(client1, 2);
    wait_for_blocks(client2, 2);

    // Disconnect the nodes to create a fork
    client1
        .disconnect_node(&url2.to_string())
        .expect("Failed to disconnect peers");

    wait_for_connection(client1, 1);
    wait_for_connection(client2, 1);

    let fork1 = client1
        .generate_to_address(branch_length, address1)
        .unwrap();

    let address2 = client2.get_address().unwrap();
    let fork2 = client2
        .generate_to_address(branch_length, address2)
        .unwrap();

    wait_for_blocks(client1, shared_blocks_count + branch_length);
    wait_for_blocks(client2, shared_blocks_count + branch_length);

    assert_eq!(fork1.len() + fork2.len(), (branch_length * 2) as usize);

    client1
        .onetry_node(&url2.to_string())
        .expect("Failed to connect to the other peer");

    wait_for_connection(client1, 2);
    wait_for_connection(client2, 2);
    std::thread::sleep(std::time::Duration::from_secs(1));

    let anchor = client1.get_block_hash(0).unwrap()[..].to_vec();

    let mut fork_test_data1 = ForkTestData::new(fork1, 0, 0);

    let mut fork_test_data2 = ForkTestData::new(fork2, 0, 0);

    let (block_hashes, bfs_order1, bfs_order2) = check_fork_bfs_order::<T>(
        &shared_blocks,
        &fork_test_data1,
        &fork_test_data2,
        &adapter_client,
        anchor.clone(),
    );
    assert!(bfs_order1 == block_hashes || bfs_order2 == block_hashes);

    fork_test_data1.update_excluded(2, 4);
    fork_test_data2.update_excluded(4, 6);
    let (block_hashes, bfs_order1, bfs_order2) = check_fork_bfs_order::<T>(
        &shared_blocks,
        &fork_test_data1,
        &fork_test_data2,
        &adapter_client,
        anchor.clone(),
    );
    assert!(bfs_order1 == block_hashes || bfs_order2 == block_hashes);

    fork_test_data1.update_excluded(0, 6);
    fork_test_data2.update_excluded(4, 6);
    let (block_hashes, bfs_order1, bfs_order2) = check_fork_bfs_order::<T>(
        &shared_blocks,
        &fork_test_data1,
        &fork_test_data2,
        &adapter_client,
        anchor.clone(),
    );
    assert!(bfs_order1 == block_hashes || bfs_order2 == block_hashes);
}

#[test]
fn btc_bfs_order() {
    test_bfs_order::<BtcNetwork>()
}

#[test]
fn doge_bfs_order() {
    test_bfs_order::<DogeNetwork>()
}

// This test makes use of mainnet data. It first syncs the headerchain until the adapter
// checkpoint is passed and then requests 10 blocks, from 350,990 to 350,999.
#[test]
fn test_btc_mainnet_data() {
    let logger = no_op_logger();
    let headers_data_path =
        std::env::var("HEADERS_DATA_PATH").expect("Failed to get test data path env variable");
    let blocks_data_path =
        std::env::var("BLOCKS_DATA_PATH").expect("Failed to get test data path env variable");

    let genesis: BlockHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        .parse()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let bitcoind_addr = ic_btc_adapter_test_utils::bitcoind::mock_bitcoin::<bitcoin::Network>(
        rt.handle(),
        headers_data_path,
        blocks_data_path,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) =
        start_active_adapter_and_client(&rt, vec![bitcoind_addr], logger, BtcNetwork::Bitcoin);
    sync_headers_until_checkpoint(&adapter_client, genesis[..].to_vec());

    // Block 350,989's block hash.
    let anchor: BlockHash = "0000000000000000035908aacac4c97fb4e172a1758bbbba2ee2b188765780eb"
        .parse()
        .unwrap();

    let blocks =
        sync_blocks::<BtcNetwork>(&adapter_client, &mut vec![], anchor[..].to_vec(), 10, 250);
    assert_eq!(blocks.len(), 10);
}

// This test makes use of testnet data. It first syncs the headerchain until the adapter
// checkpoint is passed and then requests 9 blocks.
#[test]
fn test_btc_testnet_data() {
    let logger = no_op_logger();
    let headers_data_path = std::env::var("TESTNET_HEADERS_DATA_PATH")
        .expect("Failed to get test data path env variable");
    let blocks_data_path = std::env::var("TESTNET_BLOCKS_DATA_PATH")
        .expect("Failed to get test data path env variable");

    let genesis: BlockHash = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
        .parse()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let bitcoind_addr = ic_btc_adapter_test_utils::bitcoind::mock_bitcoin::<bitcoin::Network>(
        rt.handle(),
        headers_data_path,
        blocks_data_path,
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (adapter_client, _path) =
        start_active_adapter_and_client(&rt, vec![bitcoind_addr], logger, BtcNetwork::Testnet);
    sync_headers_until_checkpoint(&adapter_client, genesis[..].to_vec());

    let anchor: BlockHash = "0000000000ec75f32a0805740a6fa1364cc1683e419e915d99892db97c3e80b2"
        .parse()
        .unwrap();

    let blocks =
        sync_blocks::<BtcNetwork>(&adapter_client, &mut vec![], anchor[..].to_vec(), 9, 250);
    assert_eq!(blocks.len(), 9);
}
